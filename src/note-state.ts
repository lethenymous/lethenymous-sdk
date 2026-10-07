import type { Note, NoteState } from "./types.js";

/** Consumption overrides conflicting legacy state. */
export function canonicalNoteState(note: Note): NoteState {
  return note.spent === true ? "spent" : note.state ?? "available";
}
