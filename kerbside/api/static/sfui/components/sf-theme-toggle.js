/**
 * <sf-theme-toggle> -- the Shaken Fist theme preference control.
 *
 * A compact three-state segmented control: Auto / Light / Dark.
 * Three explicit states rather than a cycling button, so the
 * current choice is always visible and "auto" is discoverable
 * rather than a hidden mode.
 *
 * Data in, events out. The component renders the control and
 * reports the user's choice; it never reads or writes the
 * cookie or the document element. The host page wires the
 * event to the sfui theme boot script (../sf-theme.js):
 *
 *   const toggle = document.querySelector('sf-theme-toggle');
 *   toggle.preference = sfTheme.preference;
 *   toggle.addEventListener('sf-theme-changed',
 *       (e) => sfTheme.set(e.detail.preference));
 *
 * Properties:
 *   preference  'auto' | 'light' | 'dark'. Reflected as an
 *               attribute; set it to move the control from the
 *               page.
 *
 * Events:
 *   sf-theme-changed  Fired on user selection (click or arrow
 *                     keys), with {detail: {preference}}. Not
 *                     fired when the page sets `preference`
 *                     itself.
 *
 * Styling comes entirely from the sfui design tokens
 * (../tokens.css), with fallbacks matching the dark defaults
 * so the control degrades sanely on a page that forgot the
 * stylesheet.
 */
import {LitElement, html, css} from '../lit-core.min.js';

const OPTIONS = [
    {id: 'auto', label: 'Auto'},
    {id: 'light', label: 'Light'},
    {id: 'dark', label: 'Dark'},
];

class SfThemeToggle extends LitElement {
    static properties = {
        preference: {type: String, reflect: true},
    };

    static styles = css`
        :host {
            display: inline-block;
        }
        [role='radiogroup'] {
            display: inline-flex;
            border: 1px solid var(--sf-border, #2a2d3a);
            border-radius: var(--sf-radius, 6px);
            overflow: hidden;
            background: var(--sf-surface, #1a1d27);
        }
        button {
            appearance: none;
            background: none;
            border: none;
            color: var(--sf-text-dim, #8b8fa3);
            cursor: pointer;
            font: inherit;
            font-size: 0.8em;
            line-height: 1;
            padding: 5px 10px;
        }
        button:hover {
            color: var(--sf-text, #e1e4ed);
        }
        button[aria-checked='true'] {
            background: var(--sf-accent, #6c9eff);
            color: var(--sf-bg, #0f1117);
        }
    `;

    constructor() {
        super();
        this.preference = 'auto';
    }

    render() {
        return html`
            <div role="radiogroup" aria-label="Color theme">
                ${OPTIONS.map((option) => html`
                    <button
                        role="radio"
                        aria-checked=${option.id === this.preference
                            ? 'true' : 'false'}
                        tabindex=${option.id === this.preference
                            ? '0' : '-1'}
                        data-id=${option.id}
                        @click=${() => this._select(option.id)}
                        @keydown=${this._onKeydown}>
                        ${option.label}
                    </button>`)}
            </div>`;
    }

    _select(id) {
        if (id === this.preference) {
            return;
        }
        this.preference = id;
        this.dispatchEvent(new CustomEvent('sf-theme-changed', {
            detail: {preference: id},
            bubbles: true,
            composed: true,
        }));
    }

    _onKeydown(event) {
        const delta = {ArrowRight: 1, ArrowLeft: -1}[event.key];
        if (!delta) {
            return;
        }
        event.preventDefault();
        const index = OPTIONS.findIndex(
            (option) => option.id === this.preference);
        const next = OPTIONS[
            (index + delta + OPTIONS.length) % OPTIONS.length];
        this._select(next.id);
        this.updateComplete.then(() => {
            const button = this.renderRoot.querySelector(
                `button[data-id="${next.id}"]`);
            if (button) {
                button.focus();
            }
        });
    }
}

customElements.define('sf-theme-toggle', SfThemeToggle);
