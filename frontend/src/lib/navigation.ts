export type AppPage = 'My work' | 'Products' | 'Activity' | 'Administration'
export function pageFromLocation(search: string): AppPage {
  const value = new URLSearchParams(search).get('page')
  if (value === 'Activity' || value === 'My work') return value
  if (value === 'Access' || value === 'Administration') return 'Administration'
  return 'Products'
}
