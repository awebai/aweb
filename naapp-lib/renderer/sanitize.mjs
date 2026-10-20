import DOMPurify from 'dompurify';
import MarkdownIt from 'markdown-it';

// The only HTML sink and Trusted Types policy belong to DOMPurify. No host or
// widget can inject markup, install plugins, or widen the sanitizer catalog.
const markdown = new MarkdownIt({ html: false, linkify: false, typographer: false });
export function safeLink(value) {
  try {
    let decoded = value;
    for (let n = 0; n < 8; n++) {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    }
    decoded = decoded.replace(/[\s\u0000-\u001f\u007f]/gu, '');
    const url = new URL(decoded);
    if (url.protocol !== 'https:' || url.username || url.password) return null;
    // Decode only for the safety check. URL-encoded path delimiters retain
    // their original meaning in the destination actually opened.
    const original = new URL(value);
    if (original.protocol !== 'https:' || original.username || original.password) return null;
    return original;
  } catch { return null; }
}
markdown.validateLink = value => safeLink(value) !== null;
markdown.renderer.rules.image = (tokens, index) => markdown.utils.escapeHtml(tokens[index].content);
markdown.renderer.rules.link_open = (tokens, index, options, env, self) => {
  const token = tokens[index];
  const url = safeLink(token.attrGet('href'));
  if (!url) return '';
  token.attrSet('href', url.href);
  token.attrSet('rel', 'noopener noreferrer');
  token.attrSet('target', '_blank');
  token.attrSet('referrerpolicy', 'no-referrer');
  return self.renderToken(tokens, index, options);
};
export function renderMarkdown(target, text) {
  target.innerHTML = DOMPurify.sanitize(markdown.render(text), {
    RETURN_TRUSTED_TYPE: true,
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 's', 'blockquote', 'ul', 'ol', 'li', 'pre', 'code', 'a', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'],
    ALLOWED_ATTR: ['href', 'title', 'rel', 'target', 'referrerpolicy', 'start'],
    ALLOW_DATA_ATTR: false, ALLOW_ARIA_ATTR: false,
    ADD_URI_SAFE_ATTR: ['rel', 'target', 'referrerpolicy'],
    ALLOWED_URI_REGEXP: /^https:\/\//i,
  });
}
