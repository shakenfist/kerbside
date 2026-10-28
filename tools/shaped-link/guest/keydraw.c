/*
 * keydraw: a minimal static PID 1 for the shaped-link latency rig.
 *
 * It loads virtio-gpu and evdev, takes KMS master on /dev/dri/card0,
 * paints a static "text" background, then does two things on the same
 * framebuffer (and therefore the same SPICE display channel):
 *
 *   - toggles the colour of a small "key box" in the top left corner on
 *     every key press, flushing only that box with DIRTYFB. This is the
 *     draw the client times, from send_key to the first surface_drawn
 *     whose rect intersects the box.
 *   - optionally animates a large "activity" rectangle well to the right
 *     of the key box at a fixed frame rate, to load the display channel.
 *     A smooth plasma with some per-pixel noise; the noise defeats
 *     spice-server's image compression, so it sets the offered bitrate.
 *
 * Kernel command line knobs (all optional):
 *   kd.fps=N    activity frame rate (0 disables the activity; default 0)
 *   kd.w=W      activity width  (default 640)
 *   kd.h=H      activity height (default 480)
 *   kd.noise=B  low bits of per-pixel noise, 0..8 (default 3)
 *   kd.delay=S  seconds after boot before the activity starts
 *               (default 0). spice-server 0.15.2 segfaults if a client
 *               connects while video streams already exist, so a run
 *               that lets spice-server stream the activity starts it
 *               only after the client has connected.
 *   kd.frames=N stop the activity after frame N, leaving frame N on the
 *               screen (0, the default, never stops). Pressing F12 stops
 *               it at once, drawing frame N in place of whichever frame
 *               is next; F12 does nothing with kd.frames=0.
 *
 * Activity frames are numbered from 0 in the order they are drawn, and
 * frame n is a function of n alone: its plasma phase is n, and its noise
 * is the noise generator's output from step n * width * height on. So the
 * picture left by a freeze is the same in every run, however long the run
 * took to get there, which is what lets a client's screenshot of it be
 * compared with a reference. F12 reaches frame N's noise without drawing
 * the frames before it (see xorshift_jump).
 *
 * The box and the activity are more than 32 pixels apart horizontally,
 * so qemu's column-sliced update path never emits a single drawable
 * that covers both.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <math.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <drm/drm.h>
#include <drm/drm_mode.h>

#define BOX_X 16
#define BOX_Y 16
#define BOX_W 96
#define BOX_H 96

static const char *mods[] = {
    "/m/virtio_dma_buf.ko.xz", "/m/drm.ko.xz", "/m/drm_kms_helper.ko.xz",
    "/m/drm_shmem_helper.ko.xz", "/m/virtio-gpu.ko.xz", "/m/evdev.ko.xz",
    NULL,
};

/* The noise generator's state before frame 0's first pixel. */
#define NOISE_SEED 0x9e3779b9u

static uint32_t *fb;
static uint32_t pitch_px, W, H, fb_id;
static int dfd;

/* The animated rectangle, and what it is drawn from. */
struct activity {
    uint32_t x, y, w, h;
    uint32_t noise_mask;
    const float *st;            /* one period of sin, 1024 steps */
};

static void die(const char *m)
{
    printf("KEYDRAW FATAL: %s: %s\n", m, strerror(errno));
    fflush(stdout);
    for (;;) {
        pause();
    }
}

static void dirty(uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    struct drm_clip_rect c = { x, y, x + w, y + h };
    struct drm_mode_fb_dirty_cmd d = {
        .fb_id = fb_id, .num_clips = 1, .clips_ptr = (uintptr_t)&c,
    };
    if (ioctl(dfd, DRM_IOCTL_MODE_DIRTYFB, &d) < 0) {
        die("DIRTYFB");
    }
}

/* One step of the activity's noise generator (xorshift32). */
static uint32_t xorshift(uint32_t x)
{
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/* Apply a 32x32 GF(2) matrix, held as the images of the basis vectors. */
static uint32_t gf2_apply(const uint32_t m[32], uint32_t x)
{
    uint32_t y = 0;
    for (int i = 0; i < 32; i++) {
        if ((x >> i) & 1) {
            y ^= m[i];
        }
    }
    return y;
}

/*
 * The noise generator's state `steps` steps after `x`, without taking
 * them. A xorshift step is linear over GF(2), so it is a 32x32 bit matrix,
 * and `steps` of them are that matrix raised to the power `steps`, which
 * squaring reaches in 64 rounds at most.
 */
static uint32_t xorshift_jump(uint32_t x, uint64_t steps)
{
    uint32_t m[32], sq[32];
    for (int i = 0; i < 32; i++) {
        m[i] = xorshift(1u << i);
    }
    while (steps) {
        if (steps & 1) {
            x = gf2_apply(m, x);
        }
        for (int i = 0; i < 32; i++) {
            sq[i] = gf2_apply(m, m[i]);
        }
        memcpy(m, sq, sizeof(m));
        steps >>= 1;
    }
    return x;
}

/*
 * Draw activity frame `f` and flush it. `*rng` must be the noise state at
 * the frame's first pixel; it is left at the next frame's.
 */
static void draw_frame(const struct activity *a, unsigned f, uint32_t *rng)
{
    const float *st = a->st;
    uint32_t r_ = *rng;
    for (uint32_t y = 0; y < a->h; y++) {
        uint32_t *row = fb + (a->y + y) * pitch_px + a->x;
        float s = st[(y * 3 + f * 7) & 1023];
        for (uint32_t x = 0; x < a->w; x++) {
            float v = st[(x * 2 + f * 5) & 1023] + s +
                      st[((x + y) * 2 + f * 11) & 1023];
            int r = 128 + 42 * v;
            int g = 128 + 42 * st[((int)(v * 170) + f * 3) & 1023];
            int b = 128 - 42 * v;
            r_ = xorshift(r_);
            row[x] = ((r ^ (r_ & a->noise_mask)) & 0xff) << 16 |
                     ((g ^ ((r_ >> 8) & a->noise_mask)) & 0xff) << 8 |
                     ((b ^ ((r_ >> 16) & a->noise_mask)) & 0xff);
        }
    }
    *rng = r_;
    dirty(a->x, a->y, a->w, a->h);
}

static int param(const char *cmdline, const char *key, int def)
{
    const char *p = strstr(cmdline, key);
    return p ? atoi(p + strlen(key)) : def;
}

/* Find the first evdev node that reports KEY_SPACE. */
static int open_keyboard(void)
{
    for (int tries = 0; tries < 100; tries++) {
        for (int i = 0; i < 16; i++) {
            char path[64];
            unsigned long keys[KEY_MAX / (8 * sizeof(long)) + 1];
            snprintf(path, sizeof(path), "/dev/input/event%d", i);
            int fd = open(path, O_RDONLY | O_NONBLOCK);
            if (fd < 0) {
                continue;
            }
            memset(keys, 0, sizeof(keys));
            if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keys)), keys) >= 0 &&
                    (keys[KEY_SPACE / (8 * sizeof(long))] >>
                     (KEY_SPACE % (8 * sizeof(long)))) & 1) {
                printf("KEYDRAW keyboard %s\n", path);
                return fd;
            }
            close(fd);
        }
        usleep(50000);
    }
    die("no keyboard evdev node");
    return -1;
}

static void paint_box(unsigned n)
{
    static const uint32_t colours[] = { 0x00ff4040, 0x0040ff40 };
    uint32_t c = colours[n & 1];
    for (uint32_t y = BOX_Y; y < BOX_Y + BOX_H; y++) {
        for (uint32_t x = BOX_X; x < BOX_X + BOX_W; x++) {
            fb[y * pitch_px + x] = c;
        }
    }
    dirty(BOX_X, BOX_Y, BOX_W, BOX_H);
}

int main(void)
{
    char cmdline[1024] = "";
    int fd;

    mkdir("/dev", 0755);
    mkdir("/proc", 0755);
    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    fd = open("/dev/console", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 1);
        dup2(fd, 2);
    }
    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, cmdline, sizeof(cmdline) - 1) < 0) {
            cmdline[0] = '\0';
        }
        close(fd);
    }
    int fps = param(cmdline, "kd.fps=", 0);
    uint32_t vw = param(cmdline, "kd.w=", 640);
    uint32_t vh = param(cmdline, "kd.h=", 480);
    int noise = param(cmdline, "kd.noise=", 3);
    int delay = param(cmdline, "kd.delay=", 0);
    int frames = param(cmdline, "kd.frames=", 0);
    uint32_t noise_mask = noise <= 0 ? 0 : noise >= 8 ? 0xff : (1u << noise) - 1;

    for (int i = 0; mods[i]; i++) {
        fd = open(mods[i], O_RDONLY);
        /* 4 == MODULE_INIT_COMPRESSED_FILE: the kernel decompresses. */
        if (fd < 0 || syscall(SYS_finit_module, fd, "", 4) < 0) {
            die(mods[i]);
        }
        close(fd);
    }
    for (int i = 0; i < 100 && (dfd = open("/dev/dri/card0", O_RDWR)) < 0; i++) {
        usleep(50000);
    }
    if (dfd < 0) {
        die("open card0");
    }
    int kfd = open_keyboard();

    uint32_t conns[8], crtcs[8], encs[8];
    struct drm_mode_card_res res = { 0 };
    if (ioctl(dfd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        die("GETRESOURCES count");
    }
    if (!res.count_connectors) {
        die("no connector");
    }
    if (!res.count_crtcs) {
        die("no crtc");
    }
    /* The arrays below hold eight of each; the kernel fills in at most
     * the counts passed, so clamp them rather than trust the device. */
    res.count_connectors = res.count_connectors > 8 ? 8 : res.count_connectors;
    res.count_crtcs = res.count_crtcs > 8 ? 8 : res.count_crtcs;
    res.count_encoders = res.count_encoders > 8 ? 8 : res.count_encoders;
    res.connector_id_ptr = (uintptr_t)conns;
    res.crtc_id_ptr = (uintptr_t)crtcs;
    res.encoder_id_ptr = (uintptr_t)encs;
    res.count_fbs = 0;
    if (ioctl(dfd, DRM_IOCTL_MODE_GETRESOURCES, &res) < 0) {
        die("GETRESOURCES");
    }
    struct drm_mode_modeinfo modes[32];
    struct drm_mode_get_connector conn = { .connector_id = conns[0] };
    if (ioctl(dfd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0) {
        die("GETCONNECTOR count");
    }
    conn.count_props = 0;
    conn.count_encoders = 0;
    conn.count_modes = conn.count_modes > 32 ? 32 : conn.count_modes;
    conn.modes_ptr = (uintptr_t)modes;
    if (ioctl(dfd, DRM_IOCTL_MODE_GETCONNECTOR, &conn) < 0 || !conn.count_modes) {
        die("GETCONNECTOR");
    }
    W = modes[0].hdisplay;
    H = modes[0].vdisplay;

    struct drm_mode_create_dumb cd = { .width = W, .height = H, .bpp = 32 };
    if (ioctl(dfd, DRM_IOCTL_MODE_CREATE_DUMB, &cd) < 0) {
        die("CREATE_DUMB");
    }
    struct drm_mode_fb_cmd fbc = {
        .width = W, .height = H, .pitch = cd.pitch, .bpp = 32, .depth = 24,
        .handle = cd.handle,
    };
    if (ioctl(dfd, DRM_IOCTL_MODE_ADDFB, &fbc) < 0) {
        die("ADDFB");
    }
    fb_id = fbc.fb_id;
    struct drm_mode_map_dumb md = { .handle = cd.handle };
    if (ioctl(dfd, DRM_IOCTL_MODE_MAP_DUMB, &md) < 0) {
        die("MAP_DUMB");
    }
    fb = mmap(NULL, cd.size, PROT_READ | PROT_WRITE, MAP_SHARED, dfd, md.offset);
    if (fb == MAP_FAILED) {
        die("mmap");
    }
    pitch_px = cd.pitch / 4;

    /* Static background: pseudo-text glyph cells, 8x16, on dark blue. */
    uint32_t seed = 12345;
    for (uint32_t cy = 0; cy < H / 16; cy++) {
        for (uint32_t cx = 0; cx < W / 8; cx++) {
            seed = seed * 1103515245 + 12345;
            int blank = (seed >> 16) % 5 == 0;
            for (uint32_t y = 0; y < 16; y++) {
                seed = seed * 1103515245 + 12345;
                uint8_t bits = blank || y < 3 || y > 13 ? 0 : (seed >> 16) & 0x7e;
                for (uint32_t x = 0; x < 8; x++) {
                    fb[(cy * 16 + y) * pitch_px + cx * 8 + x] =
                        (bits >> x) & 1 ? 0x00c0c0c0 : 0x00102040;
                }
            }
        }
    }
    struct drm_mode_crtc crtc = {
        .crtc_id = crtcs[0], .fb_id = fb_id, .set_connectors_ptr = (uintptr_t)conns,
        .count_connectors = 1, .mode = modes[0], .mode_valid = 1,
    };
    if (ioctl(dfd, DRM_IOCTL_MODE_SETCRTC, &crtc) < 0) {
        die("SETCRTC");
    }
    unsigned presses = 0;
    paint_box(presses);
    dirty(0, 0, W, H);

    /* Activity rect: right-aligned, clear of the key box's columns. */
    if (vw > W - 256) {
        vw = W - 256;
    }
    if (vh > H - 32) {
        vh = H - 32;
    }
    uint32_t vx = W - vw - 16, vy = (H - vh) / 2;
    printf("KEYDRAW START %ux%u box %ux%u@%u,%u activity %ux%u@%u,%u fps=%d noise=%d delay=%d frames=%d\n",
           W, H, BOX_W, BOX_H, BOX_X, BOX_Y, vw, vh, vx, vy, fps, noise, delay, frames);
    fflush(stdout);

    float *st = malloc(sizeof(float) * 1024);
    for (int i = 0; i < 1024; i++) {
        st[i] = sinf(i * 2 * (float)M_PI / 1024);
    }
    struct activity act = {
        .x = vx, .y = vy, .w = vw, .h = vh, .noise_mask = noise_mask, .st = st,
    };
    struct timespec next;
    clock_gettime(CLOCK_MONOTONIC, &next);
    time_t activity_from = next.tv_sec + delay;
    long period = fps > 0 ? 1000000000L / fps : 0;
    uint32_t rng = NOISE_SEED;
    unsigned drawn = 0;         /* the next activity frame's number */
    int frozen = 0;
    for (;;) {
        /* Paced: an activity runs, or is waiting for kd.delay to pass. */
        int paced = fps > 0 && !frozen;
        if (paced && next.tv_sec >= activity_from) {
            draw_frame(&act, drawn, &rng);
            if (frames > 0 && drawn == (unsigned)frames) {
                frozen = 1;
                printf("KEYDRAW FROZEN frame %u after the last frame\n", drawn);
                fflush(stdout);
            }
            drawn++;
        }
        if (paced) {
            next.tv_nsec += period;
            while (next.tv_nsec >= 1000000000L) {
                next.tv_nsec -= 1000000000L;
                next.tv_sec++;
            }
        }

        /*
         * Wait for key events until the next frame is due, handling any
         * press immediately so the activity never delays the key box.
         */
        for (;;) {
            int timeout_ms = -1;
            if (fps > 0 && !frozen) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                long ms = (next.tv_sec - now.tv_sec) * 1000 +
                          (next.tv_nsec - now.tv_nsec) / 1000000;
                if (ms <= 0) {
                    break;
                }
                timeout_ms = (int)ms;
            }
            struct pollfd p = { .fd = kfd, .events = POLLIN };
            if (poll(&p, 1, timeout_ms) <= 0) {
                if (fps > 0 && !frozen) {
                    break;
                }
                continue;
            }
            struct input_event ev[16];
            ssize_t n = read(kfd, ev, sizeof(ev));
            for (ssize_t i = 0; i < n / (ssize_t)sizeof(ev[0]); i++) {
                if (ev[i].type != EV_KEY || ev[i].value != 1) {
                    continue;
                }
                if (ev[i].code != KEY_F12) {
                    paint_box(++presses);
                } else if (fps > 0 && frames > 0 && !frozen) {
                    rng = xorshift_jump(NOISE_SEED, (uint64_t)frames * vw * vh);
                    draw_frame(&act, frames, &rng);
                    frozen = 1;
                    printf("KEYDRAW FROZEN frame %d on F12 after %u frames\n", frames, drawn);
                    fflush(stdout);
                }
            }
        }
    }
}
