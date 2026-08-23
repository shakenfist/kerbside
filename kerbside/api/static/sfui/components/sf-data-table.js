/**
 * <sf-data-table> -- the Shaken Fist data table.
 *
 * Data in, events out. The component owns presentation and
 * interaction (rendering cells, column sorting, action
 * buttons) and knows nothing about what the data means: what
 * a count links to, which tone a status deserves, what an
 * action does -- that judgement belongs to the page, which
 * maps its own state onto the descriptors below. The split is
 * what makes the table reusable across Shaken Fist UIs, and
 * it is also why cells are structured descriptors rather than
 * markup: the page never hands the component HTML, so cell
 * content is always rendered as text.
 *
 * Properties:
 *   columns    Array of {label, align, sortable, sorted,
 *              title}. `align: 'num'` right-aligns the column
 *              for numeric data; anything else is left-aligned.
 *              `sortable: true` makes the header a button the
 *              viewer can sort by. `sorted: 'asc'` or
 *              `sorted: 'desc'` declares that the rows already
 *              arrive in that column's order, which is what
 *              lets the first paint name the order it is
 *              showing (see Sorting below). `title` becomes a
 *              header tooltip. All but `label` are optional.
 *   rows       Array of rows, one array of cells per row, in
 *              the order the page considers natural (the
 *              order sorting returns to). A cell is either a
 *              primitive, rendered as plain text, or an
 *              object {sortValue, parts} where each part is
 *              one of:
 *                {text, tone, href, title, small, block}
 *                  a text span; with `href` a link opened in
 *                  a new tab. `small` shrinks it, `block`
 *                  puts it on its own line. `href` is trusted
 *                  page data, though schemes other than http,
 *                  https and mailto are refused and render as
 *                  plain text.
 *                {badge: text, tone, title}
 *                  an outline pill.
 *                {ribbon: [tone, ...], title}
 *                  a row of small boxes, one per entry -- a
 *                  decorative sparkline, hidden from
 *                  assistive tech, so pair it with a textual
 *                  part.
 *                {button: {label, action, data, disabled,
 *                          tone}}
 *                  an action button; see the event below.
 *              An object cell without `parts` is treated as a
 *              single part, and null parts are skipped, so a
 *              page can write a conditional parts list without
 *              filtering it. Tones are 'accent', 'green',
 *              'amber', 'red', 'purple', 'pink', 'teal',
 *              'orange' or 'dim', naming the matching design
 *              token; anything else falls back to the default
 *              text color.
 *   emptyText  Message shown instead of the table when `rows`
 *              is empty (nothing at all is rendered when this
 *              is empty too). Keeping the element in the DOM
 *              and setting this, rather than swapping the
 *              element out for a message, is what preserves
 *              sort state across refreshes. Also settable as
 *              the empty-text attribute.
 *   footnote   Small dim text under the table when non-empty.
 *              Shown only alongside the table: with empty
 *              `rows` the empty state renders alone. Also
 *              settable as the footnote attribute.
 *   caption    Optional accessible name for the table,
 *              rendered as a visually hidden <caption> so
 *              assistive tech announces what the table holds;
 *              a page whose heading already names the table
 *              can omit it. Also settable as the caption
 *              attribute.
 *
 * Sorting never mutates `rows`: the component renders a
 * sorted view, so a page replacing `rows` on a poll tick
 * keeps the viewer's chosen order. Sort state is tied to
 * column indices and deliberately survives a `columns`
 * replacement (a page must be free to rebuild an equivalent
 * columns array every tick), so a page that switches an
 * element between different table shapes should use one
 * element per shape. If a replacement drops the sorted
 * column or its sortable flag, the sort silently returns to
 * the natural order rather than persisting where no header
 * could announce or clear it. The sort key for a cell is
 * `sortValue` when present, the cell itself for primitives,
 * else the first part's text or badge; numbers compare
 * numerically when both keys are numbers, anything else
 * compares as case-insensitive text, and missing keys sort
 * last in both directions.
 *
 * Two things a table must say before it is touched: that its
 * columns sort at all, and which order it is currently in.
 * Every sortable header therefore carries a muted double
 * arrow, and the column the table is ordered by carries a
 * solid one instead. Before the viewer sorts anything, that
 * ordered column is whichever column declares `sorted`, which
 * the page uses to name the natural order it supplies -- the
 * component takes the declaration at its word and reorders
 * nothing, so a page that declares an order its rows are not
 * in is lying to the viewer on its own account. A natural
 * order with several keys names its primary one (ties then
 * fall the way the page supplied them), and a column need not
 * be `sortable` to be declared: a table the viewer cannot
 * re-sort can still say what it is sorted by. Only the first
 * declaration counts; later ones are ignored.
 *
 * A header click cycles ascending, descending, then back to
 * the natural order. The declared column is the exception,
 * having only two states to offer rather than three: a click
 * flips it to the opposite direction, and a click from
 * anywhere else returns the table to the natural order it
 * already describes.
 *
 * Events:
 *   sf-data-table-action  Fired when an enabled button part
 *                         is clicked, with {detail: {action,
 *                         data, rowIndex}}. `rowIndex` indexes
 *                         `rows` as supplied (natural order);
 *                         `data` is the page's own payload and
 *                         the reliable channel. What the
 *                         action does belongs to the page; the
 *                         table only reports the click.
 *   sf-data-table-sort    Fired on user sort changes (never
 *                         when the page replaces data), with
 *                         {detail: {column, direction}} where
 *                         direction is 'asc', 'desc' or null
 *                         for the return to natural order --
 *                         null even where a column declares
 *                         that order, since the page named it
 *                         and knows what it is.
 *
 * Styling comes entirely from the sfui design tokens
 * (../tokens.css), with fallbacks matching the token defaults
 * so the table degrades sanely on a page that forgot the
 * stylesheet.
 */
import {css, html, LitElement, nothing} from '../lit-core.min.js';

const TONES = [
    'accent',
    'green',
    'amber',
    'red',
    'purple',
    'pink',
    'teal',
    'orange',
    'dim',
];

class SfDataTable extends LitElement {
    static properties = {
        columns: {attribute: false},
        rows: {attribute: false},
        emptyText: {type: String, attribute: 'empty-text'},
        footnote: {type: String},
        caption: {type: String},
        _sortColumn: {state: true},
        _sortDir: {state: true},
    };

    /*
     * sf.css's .sf-table is the CSS-only version of this look,
     * for server-rendered pages, and the th/td rules below copy
     * it measurement for measurement, as .action, .empty and
     * .footnote copy .sf-btn, .sf-empty and .sf-footnote. All
     * must stay visually in step: a change here belongs there
     * as well. The one deliberate departure is .pill, an
     * outline on currentColor rather than .sf-badge's tinted
     * fill: a badge sits between mono digits in a dense cell,
     * where a filled block overwhelms the row it annotates.
     */
    static styles = css`
        :host {
            display: block;
        }
        .scroll {
            max-width: 100%;
            overflow-x: auto;
        }
        table {
            width: 100%;
            min-width: max-content;
            border-collapse: collapse;
        }
        th,
        td {
            text-align: left;
            padding: var(--sf-table-cell-pad, 0.5rem 0.8rem);
            border-bottom: 1px solid var(--sf-border, #2a2d3a);
            font-size: 0.88rem;
        }
        th {
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--sf-text-dim, #8b8fa3);
        }
        td {
            font-family: var(
                --sf-font-mono,
                "SF Mono",
                Consolas,
                "Liberation Mono",
                monospace
            );
        }
        tbody tr:hover {
            background: color-mix(
                in srgb,
                var(--sf-accent, #6c9eff) 8%,
                transparent
            );
        }
        th.num,
        td.num {
            text-align: right;
        }
        th button {
            appearance: none;
            background: none;
            border: none;
            color: inherit;
            cursor: pointer;
            font: inherit;
            letter-spacing: inherit;
            text-transform: inherit;
            padding: 0;
        }
        th button:hover {
            color: var(--sf-text, #e1e4ed);
        }
        .arrow {
            margin-left: 0.35em;
        }
        /*
         * The ordered column is the one fact a viewer reads
         * before anything else in the table, so it is the one
         * header lifted out of the dim header row, and its
         * arrow is the accent rather than the text color: the
         * muted double arrow the other sortable headers carry
         * is the same glyph weight, and only color separates
         * "you may sort by this" from "you are sorted by
         * this". That muting has no rule of its own: the hint
         * inherits the header row's dim, which is what should
         * happen if the header row's color ever changes, and
         * its class exists to give the tests something to name.
         */
        th.sorted {
            color: var(--sf-text, #e1e4ed);
        }
        th.sorted .arrow {
            color: var(--sf-accent, #6c9eff);
        }
        a {
            color: var(--sf-accent, #6c9eff);
            text-decoration: none;
        }
        a:hover {
            color: var(--sf-accent-hover, #8bb4ff);
            text-decoration: underline;
        }
        .part + .part {
            margin-left: 0.45em;
        }
        .part + .part.block {
            margin-left: 0;
        }
        .block {
            display: block;
        }
        .small {
            font-size: 0.8em;
        }
        .pill {
            display: inline-block;
            border: 1px solid currentColor;
            border-radius: var(--sf-radius-sm, 4px);
            font-size: 0.78rem;
            font-weight: 600;
            padding: 1px 7px;
            white-space: nowrap;
        }
        .ribbon {
            display: inline-flex;
            gap: 2px;
            color: var(--sf-text-dim, #8b8fa3);
        }
        .ribbon span {
            width: 3px;
            height: 8px;
            border-radius: 1px;
            background: currentColor;
        }
        .action {
            appearance: none;
            background: transparent;
            border: 1px solid var(--sf-border, #2a2d3a);
            border-radius: var(--sf-radius-sm, 4px);
            color: var(--sf-text, #e1e4ed);
            cursor: pointer;
            font-family: inherit;
            font-size: 0.78rem;
            padding: 0.15rem 0.6rem;
        }
        .action:hover:enabled {
            border-color: var(--sf-accent, #6c9eff);
            color: var(--sf-accent, #6c9eff);
        }
        .action:disabled {
            background: transparent;
            border-color: var(--sf-text-dim, #8b8fa3);
            color: var(--sf-text-dim, #8b8fa3);
            cursor: default;
        }
        .empty {
            color: var(--sf-text-dim, #8b8fa3);
            font-size: 0.95rem;
            padding: 2rem;
            text-align: center;
        }
        .footnote {
            color: var(--sf-text-dim, #8b8fa3);
            font-size: 0.75rem;
            margin: 0.6rem 0 0;
        }
        caption {
            position: absolute;
            width: 1px;
            height: 1px;
            margin: -1px;
            overflow: hidden;
            clip-path: inset(50%);
            white-space: nowrap;
        }
        .accent,
        a.accent:hover {
            color: var(--sf-accent, #6c9eff);
        }
        .green,
        a.green:hover {
            color: var(--sf-green, #4ade80);
        }
        .amber,
        a.amber:hover {
            color: var(--sf-amber, #fbbf24);
        }
        .red,
        a.red:hover {
            color: var(--sf-red, #f87171);
        }
        .purple,
        a.purple:hover {
            color: var(--sf-purple, #a78bfa);
        }
        .pink,
        a.pink:hover {
            color: var(--sf-pink, #f472b6);
        }
        .teal,
        a.teal:hover {
            color: var(--sf-teal, #2dd4bf);
        }
        .orange,
        a.orange:hover {
            color: var(--sf-orange, #fb923c);
        }
        .dim,
        a.dim:hover {
            color: var(--sf-text-dim, #8b8fa3);
        }
        .action.accent,
        .action.green,
        .action.amber,
        .action.red,
        .action.purple,
        .action.pink,
        .action.teal,
        .action.orange,
        .action.dim {
            border-color: currentColor;
        }
    `;

    constructor() {
        super();
        this.columns = [];
        this.rows = [];
        this.emptyText = '';
        this.footnote = '';
        this.caption = '';
        this._sortColumn = null;
        this._sortDir = null;
    }

    render() {
        const rows = this.rows || [];
        if (!rows.length) {
            if (!this.emptyText) {
                return nothing;
            }
            return html`<div class="empty">${this.emptyText}</div>`;
        }
        const columns = this.columns || [];
        // One sort state for the whole header row, resolved once:
        // every header is describing the same fact from its own
        // column's point of view.
        const sort = this._currentSort();
        return html`
            <div class="scroll">
                <table>
                    ${
                        this.caption
                            ? html`<caption>${this.caption}</caption>`
                            : nothing
                    }
                    <thead>
                        <tr>
                            ${columns.map((column, index) =>
                                this._headerCell(column, index, sort),
                            )}
                        </tr>
                    </thead>
                    <tbody>
                        ${this._sortedView(rows).map(
                            (entry) => html`
                            <tr>
                                ${entry.row.map((cell, index) =>
                                    this._bodyCell(
                                        cell,
                                        index,
                                        entry.index,
                                    ),
                                )}
                            </tr>`,
                        )}
                    </tbody>
                </table>
            </div>
            ${
                this.footnote
                    ? html`<p class="footnote">${this.footnote}</p>`
                    : nothing
            }`;
    }

    _headerCell(column, index, sort) {
        const active = sort !== null && sort.column === index;
        const classes = [];
        if (column.align === 'num') {
            classes.push('num');
        }
        if (active) {
            classes.push('sorted');
        }
        const cls = classes.length ? classes.join(' ') : nothing;
        const title = column.title || nothing;
        const marker = this._marker(column, active, sort);
        const announced = active
            ? sort.direction === 'asc'
                ? 'ascending'
                : 'descending'
            : column.sortable
              ? 'none'
              : nothing;
        if (!column.sortable) {
            return html`
                <th scope="col"
                    class=${cls}
                    title=${title}
                    aria-sort=${announced}>
                    ${column.label}${marker}</th>`;
        }
        return html`
            <th scope="col"
                class=${cls}
                title=${title}
                aria-sort=${announced}>
                <button @click=${() => this._cycle(index)}>
                    ${column.label}${marker}
                </button>
            </th>`;
    }

    /*
     * Decorative in both spellings: the direction is on the th
     * as aria-sort, and the double arrow says nothing a screen
     * reader cannot get from the header being a button.
     */
    _marker(column, active, sort) {
        if (active) {
            return html`<span class="arrow" aria-hidden="true">${
                sort.direction === 'asc' ? '▲' : '▼'
            }</span>`;
        }
        if (!column.sortable) {
            return nothing;
        }
        return html`<span class="arrow hint"
            aria-hidden="true">⇅</span>`;
    }

    _bodyCell(cell, columnIndex, rowIndex) {
        const column = (this.columns || [])[columnIndex] || {};
        const cls = column.align === 'num' ? 'num' : nothing;
        if (cell === null || cell === undefined) {
            return html`<td class=${cls}></td>`;
        }
        if (typeof cell !== 'object') {
            return html`<td class=${cls}>${cell}</td>`;
        }
        const parts = cell.parts || [cell];
        return html`
            <td class=${cls}>
                ${parts.map((part) => this._part(part, rowIndex))}
            </td>`;
    }

    _part(part, rowIndex) {
        if (part === null || part === undefined) {
            return nothing;
        }
        if (part.button) {
            return this._buttonPart(part.button, rowIndex);
        }
        if (part.ribbon) {
            return this._ribbonPart(part);
        }
        if (part.badge !== undefined) {
            return this._badgePart(part);
        }
        return this._textPart(part);
    }

    _classes(part, extra) {
        const names = ['part'].concat(extra || []);
        if (TONES.includes(part.tone)) {
            names.push(part.tone);
        }
        if (part.small) {
            names.push('small');
        }
        if (part.block) {
            names.push('block');
        }
        return names.join(' ');
    }

    _textPart(part) {
        const title = part.title || nothing;
        if (part.href && this._safeHref(part.href)) {
            return html`<a class=${this._classes(part)}
                href=${part.href}
                target="_blank"
                rel="noopener noreferrer"
                title=${title}>${part.text}</a>`;
        }
        return html`<span class=${this._classes(part)}
            title=${title}>${part.text}</span>`;
    }

    /*
     * The URL parser rather than a regex: the WHATWG parser
     * strips the tab and newline spellings ('java\tscript:')
     * that defeat anchored pattern matching, and resolving
     * against a fixed base classifies relative and fragment
     * hrefs as https.
     */
    _safeHref(href) {
        let url;
        try {
            url = new URL(String(href), 'https://sfui.invalid/');
        } catch {
            return false;
        }
        return ['http:', 'https:', 'mailto:'].includes(url.protocol);
    }

    _badgePart(part) {
        return html`<span class=${this._classes(part, ['pill'])}
            title=${part.title || nothing}>${part.badge}</span>`;
    }

    _ribbonPart(part) {
        return html`<span class="part ribbon"
            aria-hidden="true"
            title=${part.title || nothing}>${part.ribbon.map(
                (tone) =>
                    html`<span class=${
                        TONES.includes(tone) ? tone : nothing
                    }></span>`,
            )}</span>`;
    }

    _buttonPart(spec, rowIndex) {
        return html`<button
            class=${this._classes(spec, ['action'])}
            ?disabled=${Boolean(spec.disabled)}
            @click=${() => this._action(spec, rowIndex)}>${
                spec.label
            }</button>`;
    }

    _action(spec, rowIndex) {
        if (spec.disabled) {
            return;
        }
        this.dispatchEvent(
            new CustomEvent('sf-data-table-action', {
                detail: {
                    action: spec.action,
                    data: spec.data || {},
                    rowIndex,
                },
                bubbles: true,
                composed: true,
            }),
        );
    }

    /*
     * The order the table is in: the viewer's sort where they
     * have made one, else whatever the page declared about the
     * rows it handed over, else nothing to say.
     */
    _currentSort() {
        if (this._sortColumn !== null && this._sortDir !== null) {
            return {
                column: this._sortColumn,
                direction: this._sortDir,
            };
        }
        return this._declaredSort();
    }

    _declaredSort() {
        const columns = this.columns || [];
        for (let index = 0; index < columns.length; index++) {
            const declared = columns[index].sorted;
            if (declared === 'asc' || declared === 'desc') {
                return {column: index, direction: declared};
            }
        }
        return null;
    }

    /*
     * Three states for an ordinary column, two for the declared
     * one: it starts in its declared direction, so the click
     * that would have set that direction has nothing to change
     * and returns to the natural order instead -- which is the
     * same thing said from the other side, and reachable from a
     * sort on any other column too.
     */
    _cycle(index) {
        const declared = this._declaredSort();
        if (declared !== null && declared.column === index) {
            if (this._sortColumn === null) {
                this._sortColumn = index;
                this._sortDir =
                    declared.direction === 'asc' ? 'desc' : 'asc';
            } else {
                this._sortColumn = null;
                this._sortDir = null;
            }
        } else if (this._sortColumn !== index) {
            this._sortColumn = index;
            this._sortDir = 'asc';
        } else if (this._sortDir === 'asc') {
            this._sortDir = 'desc';
        } else {
            this._sortColumn = null;
            this._sortDir = null;
        }
        this.dispatchEvent(
            new CustomEvent('sf-data-table-sort', {
                detail: {column: index, direction: this._sortDir},
                bubbles: true,
                composed: true,
            }),
        );
    }

    /*
     * A columns replacement keeps the sort (pages rebuild an
     * equivalent columns array every poll tick), unless it
     * drops the sorted column or its sortable flag, where an
     * unreachable sort would otherwise persist with no header
     * announcing it. No sort event: those are user-only.
     */
    willUpdate(changed) {
        if (!changed.has('columns') || this._sortColumn === null) {
            return;
        }
        const column = (this.columns || [])[this._sortColumn];
        if (!column || !column.sortable) {
            this._sortColumn = null;
            this._sortDir = null;
        }
    }

    _sortedView(rows) {
        if (this._sortColumn === null || this._sortDir === null) {
            return rows.map((row, index) => ({row, index}));
        }
        const column = this._sortColumn;
        const direction = this._sortDir === 'desc' ? -1 : 1;
        const entries = rows.map((row, index) => ({
            row,
            index,
            key: this._sortKey(row[column]),
        }));
        entries.sort((a, b) => {
            const keyA = a.key;
            const keyB = b.key;
            const missingA = this._missing(keyA);
            const missingB = this._missing(keyB);
            if (missingA || missingB) {
                if (missingA && missingB) {
                    return a.index - b.index;
                }
                return missingA ? 1 : -1;
            }
            const order = this._compare(keyA, keyB) * direction;
            return order !== 0 ? order : a.index - b.index;
        });
        return entries;
    }

    _sortKey(cell) {
        if (cell === null || cell === undefined) {
            return null;
        }
        if (typeof cell !== 'object') {
            return cell;
        }
        if ('sortValue' in cell) {
            return cell.sortValue;
        }
        const first = (cell.parts || [cell])[0] || {};
        if (first.text !== undefined) {
            return first.text;
        }
        if (first.badge !== undefined) {
            return first.badge;
        }
        return null;
    }

    _missing(key) {
        return (
            key === null ||
            key === undefined ||
            (typeof key === 'number' && Number.isNaN(key))
        );
    }

    _compare(keyA, keyB) {
        if (typeof keyA === 'number' && typeof keyB === 'number') {
            return keyA - keyB;
        }
        const textA = String(keyA).toLowerCase();
        const textB = String(keyB).toLowerCase();
        if (textA < textB) {
            return -1;
        }
        return textA > textB ? 1 : 0;
    }
}

customElements.define('sf-data-table', SfDataTable);
