// A refused filter form: once the console has shown this tab's content, move
// focus to the first field whose value was refused, so its reason is read.
(() => {
  const refused = document.querySelector('#filters [aria-invalid="true"]');
  if (refused) refused.focus();
})();
