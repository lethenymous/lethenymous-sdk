import type { Note, NoteState } from "./types.js";
/** Consumption overrides conflicting legacy state. */
export declare function canonicalNoteState(note: Note): NoteState;
