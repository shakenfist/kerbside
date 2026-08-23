/**
 * <sf-tabs> -- the Shaken Fist tab strip.
 *
 * Data in, events out. The component owns presentation and
 * interaction (selection, keyboard handling, notification
 * badges) and knows nothing about what the tabs mean: the
 * judgement of what is "actionable" belongs to the page, which
 * maps its own state onto the badge values below. That split is
 * what makes the strip reusable across Shaken Fist UIs.
 *
 * Properties:
 *   tabs      Array of {id, label, badge}. `badge` is null for
 *             none, {count, severity} for a numeric pill, or
 *             {severity} alone for a plain notification dot.
 *             Severity is 'info' (accent), 'attention' (amber)
 *             or 'urgent' (red).
 *   selected  The id of the selected tab. Reflected as an
 *             attribute; set it to switch tabs from the page.
 *
 * Events:
 *   sf-tab-selected  Fired on user selection (click or arrow
 *                    keys), with {detail: {id}}. Not fired when
 *                    the page sets `selected` itself. The page
 *                    owns what selection means (showing panels,
 *                    updating the URL); the strip only reports
 *                    it.
 *
 * Styling comes entirely from the sfui design tokens
 * (../tokens.css), with fallbacks matching the token defaults
 * so the strip degrades sanely on a page that forgot the
 * stylesheet.
 */
import {css, html, LitElement, nothing} from '../lit-core.min.js';

class SfTabs extends LitElement {
    static properties = {
        tabs: {attribute: false},
        selected: {type: String, reflect: true},
    };

    /*
     * sf.css's .sf-nav is the link version of this strip, for
     * site navigation, and copies the nav and button rules below
     * measurement for measurement. The two must stay visually in
     * step: a change here belongs there as well.
     */
    static styles = css`
        :host {
            display: block;
        }
        nav {
            display: flex;
            gap: 4px;
            border-bottom: 1px solid var(--sf-border, #2a2d3a);
        }
        button {
            appearance: none;
            background: none;
            border: none;
            border-bottom: 2px solid transparent;
            color: var(--sf-text-dim, #8b8fa3);
            cursor: pointer;
            font: inherit;
            padding: 8px 14px;
            display: flex;
            align-items: center;
            gap: 7px;
        }
        button:hover {
            color: var(--sf-text, #e1e4ed);
        }
        button[aria-selected='true'] {
            color: var(--sf-text, #e1e4ed);
            border-bottom-color: var(--sf-accent, #6c9eff);
        }
        .badge {
            border-radius: var(--sf-radius-lg, 8px);
            font-size: 0.75em;
            line-height: 1;
            padding: 3px 6px;
            color: var(--sf-bg, #0f1117);
        }
        .dot {
            border-radius: 50%;
            width: 8px;
            height: 8px;
            padding: 0;
        }
        .info {
            background: var(--sf-accent, #6c9eff);
        }
        .attention {
            background: var(--sf-amber, #fbbf24);
        }
        .urgent {
            background: var(--sf-red, #f87171);
        }
    `;

    constructor() {
        super();
        this.tabs = [];
        this.selected = '';
    }

    render() {
        return html`
            <nav role="tablist">
                ${(this.tabs || []).map(
                    (tab) => html`
                    <button
                        role="tab"
                        aria-selected=${
                            tab.id === this.selected ? 'true' : 'false'
                        }
                        tabindex=${
                            tab.id === this.selected ? '0' : '-1'
                        }
                        data-id=${tab.id}
                        @click=${() => this._select(tab.id)}
                        @keydown=${this._onKeydown}>
                        ${tab.label}
                        ${this._badge(tab.badge)}
                    </button>`,
                )}
            </nav>`;
    }

    _badge(badge) {
        if (!badge) {
            return nothing;
        }
        const severity = ['info', 'attention', 'urgent'].includes(
            badge.severity,
        )
            ? badge.severity
            : 'info';
        if (badge.count !== undefined && badge.count !== null) {
            return html`
                <span class="badge ${severity}">
                    ${badge.count}</span>`;
        }
        return html`
            <span class="badge dot ${severity}"
                  aria-hidden="true"></span>`;
    }

    _select(id) {
        if (id === this.selected) {
            return;
        }
        this.selected = id;
        this.dispatchEvent(
            new CustomEvent('sf-tab-selected', {
                detail: {id},
                bubbles: true,
                composed: true,
            }),
        );
    }

    _onKeydown(event) {
        const delta = {ArrowRight: 1, ArrowLeft: -1}[event.key];
        if (!delta || !this.tabs.length) {
            return;
        }
        event.preventDefault();
        const index = this.tabs.findIndex(
            (tab) => tab.id === this.selected,
        );
        const next =
            this.tabs[
                (index + delta + this.tabs.length) % this.tabs.length
            ];
        this._select(next.id);
        this.updateComplete.then(() => {
            const button = this.renderRoot.querySelector(
                `button[data-id="${CSS.escape(next.id)}"]`,
            );
            if (button) {
                button.focus();
            }
        });
    }
}

customElements.define('sf-tabs', SfTabs);
