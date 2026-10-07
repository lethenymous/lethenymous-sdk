/** Consumption overrides conflicting legacy state. */
export function canonicalNoteState(note) {
    return note.spent === true ? "spent" : note.state ?? "available";
}
