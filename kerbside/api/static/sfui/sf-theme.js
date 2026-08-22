/**
 * sfui theme boot -- resolves and stamps the color theme.
 *
 * This is page-level infrastructure, not a component: it may
 * read and write cookies and the document element precisely
 * because sfui components may not. Pages include it with a
 * plain, synchronous script tag in <head>, before the tokens
 * stylesheet:
 *
 *   <script src="/static/sfui/sf-theme.js"></script>
 *
 * Being render-blocking is the point: the data-theme attribute
 * is stamped before first paint, so there is no flash of the
 * wrong theme on load.
 *
 * The stored preference lives in the sf-theme cookie and is
 * 'light', 'dark', or absent (meaning "auto": follow the
 * operating system). The document element always receives a
 * concrete resolved value -- data-theme="light" or
 * data-theme="dark" -- which is why tokens.css carries no
 * prefers-color-scheme media queries. While the preference is
 * auto, operating system theme changes restamp the attribute
 * live.
 *
 * Page API, on window.sfTheme:
 *   preference       'auto' | 'light' | 'dark'. The stored
 *                    preference, not the resolved theme; read
 *                    document.documentElement.dataset.theme
 *                    for the resolved value.
 *   set(preference)  Store a preference and restamp. 'auto'
 *                    deletes the cookie; any value other than
 *                    'auto', 'light' or 'dark' throws. The
 *                    cookie is sf-theme, Path=/, SameSite=Lax,
 *                    Secure when the page is served over https,
 *                    expiring in one year.
 */
(function () {
    'use strict';

    var COOKIE = 'sf-theme';
    var ONE_YEAR = 31536000;
    var media = window.matchMedia('(prefers-color-scheme: dark)');

    function storedPreference() {
        var match = document.cookie.match(
            new RegExp('(?:^|;\\s*)' + COOKIE + '=(light|dark)(?:;|$)'),
        );
        return match ? match[1] : 'auto';
    }

    var preference = storedPreference();

    function stamp() {
        var resolved =
            preference === 'auto'
                ? media.matches
                    ? 'dark'
                    : 'light'
                : preference;
        document.documentElement.dataset.theme = resolved;
    }

    media.addEventListener('change', function () {
        if (preference === 'auto') {
            stamp();
        }
    });

    window.sfTheme = {
        get preference() {
            return preference;
        },
        set: function (value) {
            if (['auto', 'light', 'dark'].indexOf(value) < 0) {
                throw new Error(
                    'sfTheme.set: preference must be auto, ' +
                        'light or dark',
                );
            }
            preference = value;
            // Conditional because an unconditional Secure would
            // stop the cookie being stored at all on an http-only
            // deployment, and the preference would appear not to
            // persist. The asymmetry to know about: a browser will
            // not let an http page overwrite a Secure cookie of the
            // same name, so on a mixed-scheme origin a preference
            // set over https cannot be changed back over http --
            // the write is silently dropped. Both current consumers
            // are single-scheme, so this is noted rather than
            // handled.
            var secure =
                window.location.protocol === 'https:' ? '; Secure' : '';
            if (value === 'auto') {
                document.cookie =
                    COOKIE +
                    '=; Path=/; Max-Age=0; SameSite=Lax' +
                    secure;
            } else {
                document.cookie =
                    COOKIE +
                    '=' +
                    value +
                    '; Path=/; Max-Age=' +
                    ONE_YEAR +
                    '; SameSite=Lax' +
                    secure;
            }
            stamp();
        },
    };

    stamp();
})();
