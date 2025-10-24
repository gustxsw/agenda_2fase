/**
 * Centralized Date/Time Utilities
 *
 * TIMEZONE STANDARD:
 * - Frontend sends: UTC via .toISOString()
 * - Backend stores: UTC (no conversion)
 * - Frontend displays: Local time (America/Sao_Paulo)
 */

const BRAZIL_TIMEZONE = "America/Sao_Paulo";

/**
 * Convert a date input to UTC ISO string for sending to backend
 * @param date - Date string (YYYY-MM-DD) or Date object
 * @param time - Optional time string (HH:MM)
 * @returns UTC ISO string
 */
export function toUTCString(date: string | Date, time?: string): string {
  let dateObj: Date;

  if (typeof date === "string") {
    if (time) {
      // Combine date and time
      dateObj = new Date(`${date}T${time}:00`);
    } else {
      dateObj = new Date(date);
    }
  } else {
    dateObj = date;
  }

  return dateObj.toISOString();
}

/**
 * Format UTC date from backend to local Brazil time for display
 * @param utcDateString - UTC date string from backend
 * @param options - Formatting options
 * @returns Formatted date string in Brazil timezone
 */
export function formatToBrazilTime(
  utcDateString: string,
  options: {
    dateStyle?: "short" | "medium" | "long" | "full";
    timeStyle?: "short" | "medium" | "long" | "full";
    includeTime?: boolean;
  } = { dateStyle: "short", includeTime: true }
): string {
  const date = new Date(utcDateString);

  const formatOptions: Intl.DateTimeFormatOptions = {
    timeZone: BRAZIL_TIMEZONE,
  };

  if (options.dateStyle) {
    formatOptions.dateStyle = options.dateStyle;
  }

  if (options.includeTime && options.timeStyle) {
    formatOptions.timeStyle = options.timeStyle;
  } else if (options.includeTime) {
    formatOptions.hour = "2-digit";
    formatOptions.minute = "2-digit";
    formatOptions.hour12 = false;
  }

  return date.toLocaleString("pt-BR", formatOptions);
}

/**
 * Format UTC date to Brazil date only (no time)
 * @param utcDateString - UTC date string from backend
 * @returns Formatted date string (DD/MM/YYYY)
 */
export function formatToBrazilDate(utcDateString: string): string {
  const date = new Date(utcDateString);
  return date.toLocaleDateString("pt-BR", {
    timeZone: BRAZIL_TIMEZONE,
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

/**
 * Format UTC date to Brazil time only (no date)
 * @param utcDateString - UTC date string from backend
 * @returns Formatted time string (HH:MM)
 */
export function formatToBrazilTimeOnly(utcDateString: string): string {
  const date = new Date(utcDateString);
  return date.toLocaleTimeString("pt-BR", {
    timeZone: BRAZIL_TIMEZONE,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

/**
 * Format UTC date to Brazil date and time
 * @param utcDateString - UTC date string from backend
 * @returns Formatted date and time string (DD/MM/YYYY HH:MM)
 */
export function formatToBrazilDateTime(dateString: string) {
  if (!dateString) return "";

  // Detecta se a string já contém o offset do Brasil
  const alreadyLocalized =
    dateString.includes("-03:00") || dateString.includes("-02:00");

  const date = new Date(dateString);

  return date.toLocaleString("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    // Só aplica o fuso se a data for UTC pura (sem offset)
    ...(alreadyLocalized ? {} : { timeZone: "America/Sao_Paulo" }),
  });
}

/**
 * Get current date in YYYY-MM-DD format for date inputs
 * @returns Current date string
 */
export function getCurrentDateString(): string {
  const now = new Date();
  return now.toISOString().split("T")[0];
}

/**
 * Get date string for a specific offset from today
 * @param daysOffset - Number of days to offset (negative for past)
 * @returns Date string in YYYY-MM-DD format
 */
export function getDateWithOffset(daysOffset: number): string {
  const date = new Date();
  date.setDate(date.getDate() + daysOffset);
  return date.toISOString().split("T")[0];
}

/**
 * Get first day of current month in YYYY-MM-DD format
 * @returns First day of month string
 */
export function getFirstDayOfMonth(): string {
  const now = new Date();
  const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
  return firstDay.toISOString().split("T")[0];
}

/**
 * Get last day of current month in YYYY-MM-DD format
 * @returns Last day of month string
 */
export function getLastDayOfMonth(): string {
  const now = new Date();
  const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
  return lastDay.toISOString().split("T")[0];
}

/**
 * Convert UTC date string to local date input value (YYYY-MM-DD)
 * Used when populating date inputs from backend data
 * @param utcDateString - UTC date string from backend
 * @returns Date string in YYYY-MM-DD format
 */
export function utcToLocalDateInput(utcDateString: string): string {
  const date = new Date(utcDateString);
  // Get the date in Brazil timezone
  const brazilDate = new Date(
    date.toLocaleString("en-US", { timeZone: BRAZIL_TIMEZONE })
  );
  return brazilDate.toISOString().split("T")[0];
}

/**
 * Convert UTC date string to local time input value (HH:MM)
 * Used when populating time inputs from backend data
 * @param utcDateString - UTC date string from backend
 * @returns Time string in HH:MM format
 */
export function utcToLocalTimeInput(utcDateString: string): string {
  const date = new Date(utcDateString);
  return date.toLocaleTimeString("pt-BR", {
    timeZone: BRAZIL_TIMEZONE,
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}
