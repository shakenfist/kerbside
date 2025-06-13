from PIL import Image, ImageTk
import tkinter as tk

from ryll.common import _log
from ryll import decompressors
from ryll import scancodes


class HeadlessDisplay:
    def __init__(self):
        ...

    def set_upper_window(self, win):
        ...

    def create_window(self, display_number, width, height, input_queue):
        ...

    def get_window(self, display_number):
        ...

    def update_window(self, display_number, scheme, left, top, image_data):
        ...

    def cascade_update(self):
        ...


class TkinterDisplay:
    def __init__(self):
        self.windows = {}
        self.canvases = {}
        self.pil_images = {}
        self.tk_images = {}
        self.image_on_canvas = {}

        self.previous_images = {}
        self.previous_images_ordered = []

    def set_upper_window(self, win):
        self.upper_window = win

    def _handle_key_down(self, event):
        _log('keyboard', f'DOWN {event.keysym} ({event.keycode})')
        if event.keycode in scancodes.at_84:
            self.input_queue.put(('keydown', (scancodes.at_84[event.keycode][0], 'down')))
        else:
            _log('keyboard', 'Unknown key code!', severity='warn')

    def _handle_key_up(self, event):
        _log('keyboard', f'UP {event.keysym} ({event.keycode})')
        if event.keycode in scancodes.at_84:
            self.input_queue.put(('keyup', (scancodes.at_84[event.keycode][1], 'up')))
        else:
            _log('keyboard', 'Unknown key code!', severity='warn')

    def _handle_motion(self, event):
        self.input_queue.put(('motion', (event.x, event.y)))

    def _handle_mouse_down(self, event):
        self.input_queue.put(('mouse_down', (event.num, event.x, event.y)))

    def _handle_mouse_up(self, event):
        self.input_queue.put(('mouse_up', (event.num, event.x, event.y)))

    def _handle_mouse_wheel(self, event):
        # Allegedly does not work on Linux?
        _log('mouse', event)

    def create_window(self, display_number, width, height, input_queue):
        self.input_queue = input_queue

        if self.upper_window:
            self.windows[display_number] = tk.Toplevel(self.upper_window)
        else:
            self.windows[display_number] = tk.Tk()

        self.windows[display_number].geometry(f'{width}x{height}')
        self.windows[display_number].resizable(False, False)
        self.windows[display_number].title(f'display {display_number}')

        if input_queue:
            self.windows[display_number].bind_all(
                '<KeyPress>', self._handle_key_down)
            self.windows[display_number].bind_all(
                '<KeyRelease>', self._handle_key_up)
            self.windows[display_number].bind_all(
                '<Motion>', self._handle_motion)
            self.windows[display_number].bind_all(
                '<Button>', self._handle_mouse_down)
            self.windows[display_number].bind_all(
                '<ButtonRelease>', self._handle_mouse_up)
            self.windows[display_number].bind_all(
                '<MouseWheel>', self._handle_mouse_wheel)

        self.canvases[display_number] = tk.Canvas(
            self.windows[display_number], width=width, height=height)
        self.canvases[display_number].pack()

        # Start off with a blank image taking the entire canvas
        self.pil_images[display_number] = Image.new('RGBA', (width, height), (80, 80, 80))
        self.tk_images[display_number] = ImageTk.PhotoImage(
            self.pil_images[display_number], master=self.canvases[display_number])
        self.image_on_canvas[display_number] = \
            self.canvases[display_number].create_image(
                (width / 2), (height / 2), image=self.tk_images[display_number])
        self.canvases[display_number].update()

    def get_window(self, display_number):
        return self.windows.get(display_number)

    def update_window(self, display_number, scheme, left, top, image_data):
        display_str = f'display {display_number}'

        if scheme == 'glz':
            width, height, decompressed, img_id = decompressors.DecompressGLZ()(
                image_data, self.previous_images)

            # Store the decompressed image
            self.previous_images[img_id] = decompressed
            if img_id in self.previous_images_ordered:
                self.previous_images_ordered.remove(img_id)
            self.previous_images_ordered.append(img_id)

            # # Remove N images until we only have 100. This choice of the value 100 is based
            # # on the value of INIT_IMAGES_CAPACITY in spice-gtk's decode-glz.c, but the code
            # # isn't super clear. I think its effectively managing a memory pool and we might
            # # need to tweak this value at some point.
            # if len(previous_images_ordered) > 100:
            #     for img_id in previous_images_ordered[:len(previous_images_ordered) - 100]:
            #         if img_id in previous_images:
            #             del previous_images[img_id]
            #         previous_images_ordered.remove(img_id)
        elif scheme == 'lz':
            width, height, decompressed = decompressors.DecompressLZ()(image_data)
        else:
            _log(display_str, f'Unknown image data scheme {scheme}', severity='warn')

        _log(
            display_str, f'Image is {width}x{height} pixels at {left},{top}',
            severity='debug')

        # TODO(mikal): I think the performance of this is probably bad. It would be
        # nice to be able to more directly update the bitmap without re-creating the
        # tk image.
        pil_img = Image.frombuffer(
            'RGBA', (width, height), decompressed, 'raw', 'RGBA', 0, 1)
        self.pil_images[display_number].paste(pil_img, (left, top))
        self.tk_images[display_number] = ImageTk.PhotoImage(
            self.pil_images[display_number])
        self.canvases[display_number].itemconfig(
            self.image_on_canvas[display_number], image=self.tk_images[display_number])
        self.canvases[display_number].update()

    def cascade_update(self):
        for win in self.windows:
            self.windows[win].update()


CHOICES = {
    'none': HeadlessDisplay,
    'tkinter': TkinterDisplay
}
