// Cloudwarden: row selection for the Secrets Manager bulk actions (web/NOTICE.md).
import { computed, signal } from "@angular/core";

export class SmSelection {
  private readonly selected = signal<ReadonlySet<string>>(new Set());

  readonly count = computed(() => this.selected().size);

  has(id: string) {
    return this.selected().has(id);
  }

  ids() {
    return [...this.selected()];
  }

  toggle(id: string) {
    const next = new Set(this.selected());
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    this.selected.set(next);
  }

  allOf(rows: { id: string }[]) {
    return rows.length > 0 && rows.every((r) => this.selected().has(r.id));
  }

  toggleAll(rows: { id: string }[]) {
    this.selected.set(this.allOf(rows) ? new Set() : new Set(rows.map((r) => r.id)));
  }

  /** Drops ids that are no longer listed. */
  retain(ids: string[]) {
    const keep = new Set(ids);
    this.selected.set(new Set([...this.selected()].filter((id) => keep.has(id))));
  }

  clear() {
    this.selected.set(new Set());
  }
}
