export const catalogs = {
  en: { unavailable: 'Widget unavailable', unsupported: 'This page cannot be displayed.', destinations: 'Link destinations', progress: 'Progress', busy: 'In progress', empty: 'No records', readOnly: 'Read only', updated: 'Updated' },
  ca: { unavailable: 'Giny no disponible', unsupported: 'No es pot mostrar aquesta pàgina.', destinations: 'Destinacions dels enllaços', progress: 'Progrés', busy: 'En curs', empty: 'Cap registre', readOnly: 'Només lectura', updated: 'Actualitzat' },
};
export function messages(memberLocale, pageLocale) {
  const locale = memberLocale || pageLocale || 'en';
  const language = locale.split('-')[0];
  return { locale: language === 'ca' ? 'ca' : 'en', t: catalogs[language] || catalogs.en };
}
