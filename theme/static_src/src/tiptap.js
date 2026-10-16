// Tiptap markdown editor, exposed to static/js/rich-text.js.
import { Editor } from '@tiptap/core';
import { CharacterCount, Placeholder } from '@tiptap/extensions';
import { Markdown } from '@tiptap/markdown';
import { StarterKit } from '@tiptap/starter-kit';

window.PsstTiptap = { Editor, StarterKit, Markdown, CharacterCount, Placeholder };
