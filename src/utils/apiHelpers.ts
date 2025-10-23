/**
 * Get the API URL based on the current environment
 * @returns The API URL for the current environment
 */
export const getApiUrl = (): string => {
  if (
    window.location.hostname === "cartaoquiroferreira.com.br" ||
    window.location.hostname === "www.cartaoquiroferreira.com.br"
  ) {
    return "https://www.cartaoquiroferreira.com.br";
  }
  return "http://localhost:3001";
};
