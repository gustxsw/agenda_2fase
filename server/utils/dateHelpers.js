/**
 * Server-side Date/Time Utilities
 *
 * TIMEZONE STANDARD:
 * - Receive from frontend: UTC ISO strings
 * - Store in database: UTC (no conversion)
 * - Send to frontend: UTC ISO strings
 * - Display formatting: Done on frontend
 */

/**
 * Ensure date is stored as UTC ISO string
 * @param {string|Date} date - Date to convert
 * @returns {string} UTC ISO string
 */
function toUTCString(date) {
  if (!date) return null;

  const dateObj = typeof date === "string" ? new Date(date) : date;
  return dateObj.toISOString();
}

/**
 * Format date for Brazil timezone display (server-side only when needed)
 * @param {string} utcDateString - UTC date string
 * @returns {string} Formatted date in Brazil time
 */
function formatToBrazilTime(utcDateString) {
  if (!utcDateString) return "";

  const date = new Date(utcDateString);
  return date.toLocaleString("pt-BR", {
    timeZone: "America/Sao_Paulo",
    dateStyle: "short",
    timeStyle: "short",
  });
}

/**
 * Format date for Brazil timezone (date only)
 * @param {string} utcDateString - UTC date string
 * @returns {string} Formatted date (DD/MM/YYYY)
 */
function formatToBrazilDate(utcDateString) {
  if (!utcDateString) return "";

  const date = new Date(utcDateString);
  return date.toLocaleDateString("pt-BR", {
    timeZone: "America/Sao_Paulo",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

/**
 * Format time for Brazil timezone (time only)
 * @param {string} utcDateString - UTC date string
 * @returns {string} Formatted time (HH:MM)
 */
function formatToBrazilTimeOnly(utcDateString) {
  if (!utcDateString) return "";

  const date = new Date(utcDateString);
  return date.toLocaleTimeString("pt-BR", {
    timeZone: "America/Sao_Paulo",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/**
 * Add years to a date
 * @param {Date} date - Starting date
 * @param {number} years - Number of years to add
 * @returns {string} UTC ISO string
 */
function addYears(date, years) {
  const newDate = new Date(date);
  newDate.setFullYear(newDate.getFullYear() + years);
  return newDate.toISOString();
}

/**
 * Add days to a date
 * @param {Date} date - Starting date
 * @param {number} days - Number of days to add
 * @returns {string} UTC ISO string
 */
function addDays(date, days) {
  const newDate = new Date(date);
  newDate.setDate(newDate.getDate() + days);
  return newDate.toISOString();
}

export {
  toUTCString,
  formatToBrazilTime,
  formatToBrazilDate,
  formatToBrazilTimeOnly,
  addYears,
  addDays,
};
