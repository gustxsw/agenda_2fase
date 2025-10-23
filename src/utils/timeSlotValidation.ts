// Time slot validation utilities for professional scheduling

export type SlotDuration = 15 | 30 | 60;

/**
 * Validates if a time string is in the correct format (HH:mm)
 */
export const isValidTimeFormat = (time: string): boolean => {
  const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
  return timeRegex.test(time);
};

/**
 * Converts time string to minutes since midnight
 */
export const timeToMinutes = (time: string): number => {
  const [hours, minutes] = time.split(':').map(Number);
  return hours * 60 + minutes;
};

/**
 * Converts minutes since midnight to time string
 */
export const minutesToTime = (minutes: number): string => {
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
};

/**
 * Validates if a time fits within the configured slot duration
 */
export const validateTimeSlot = (time: string, slotDuration: SlotDuration): {
  isValid: boolean;
  error?: string;
  suggestedTime?: string;
} => {
  if (!isValidTimeFormat(time)) {
    return {
      isValid: false,
      error: 'Formato de horário inválido. Use o formato HH:mm (ex: 09:30)'
    };
  }

  const minutes = timeToMinutes(time);
  const remainder = minutes % slotDuration;

  if (remainder === 0) {
    return { isValid: true };
  }

  // Calculate the nearest valid times
  const previousSlot = minutes - remainder;
  const nextSlot = minutes + (slotDuration - remainder);

  const suggestedPrevious = minutesToTime(previousSlot);
  const suggestedNext = minutesToTime(nextSlot);

  return {
    isValid: false,
    error: `Horário deve ser múltiplo de ${slotDuration} minutos. Horários válidos mais próximos: ${suggestedPrevious} ou ${suggestedNext}`,
    suggestedTime: suggestedPrevious
  };
};

/**
 * Gets all valid time slots for a given duration within business hours
 */
export const getValidTimeSlots = (
  slotDuration: SlotDuration,
  startHour: number = 7,
  endHour: number = 18
): string[] => {
  const slots: string[] = [];
  const startMinutes = startHour * 60;
  const endMinutes = endHour * 60;

  for (let minutes = startMinutes; minutes < endMinutes; minutes += slotDuration) {
    slots.push(minutesToTime(minutes));
  }

  return slots;
};

/**
 * Formats time for display with better readability
 */
export const formatTimeDisplay = (time: string): string => {
  if (!isValidTimeFormat(time)) return time;
  
  const [hours, minutes] = time.split(':');
  const hour24 = parseInt(hours);
  
  return `${hours}:${minutes}`;
};

/**
 * Gets the next valid time slot based on current time and slot duration
 */
export const getNextValidSlot = (
  currentTime: string,
  slotDuration: SlotDuration
): string => {
  if (!isValidTimeFormat(currentTime)) {
    return '09:00';
  }

  const minutes = timeToMinutes(currentTime);
  const remainder = minutes % slotDuration;
  
  if (remainder === 0) {
    return currentTime;
  }

  const nextSlot = minutes + (slotDuration - remainder);
  return minutesToTime(nextSlot);
};

/**
 * Validates business hours
 */
export const isWithinBusinessHours = (
  time: string,
  startHour: number = 7,
  endHour: number = 18
): boolean => {
  if (!isValidTimeFormat(time)) return false;
  
  const minutes = timeToMinutes(time);
  const startMinutes = startHour * 60;
  const endMinutes = endHour * 60;
  
  return minutes >= startMinutes && minutes < endMinutes;
};

/**
 * Gets slot duration description for UI
 */
export const getSlotDurationDescription = (duration: SlotDuration): string => {
  switch (duration) {
    case 15:
      return 'Slots de 15 minutos - Horários válidos: 09:00, 09:15, 09:30, 09:45...';
    case 30:
      return 'Slots de 30 minutos - Horários válidos: 09:00, 09:30, 10:00, 10:30...';
    case 60:
      return 'Slots de 60 minutos - Horários válidos: 09:00, 10:00, 11:00, 12:00...';
    default:
      return `${duration} minutos`;
  }
};

/**
 * Validates if a time conflicts with existing appointments
 */
export const checkTimeConflict = (
  newTime: string,
  newDate: string,
  existingAppointments: Array<{ date: string; time: string }>,
  slotDuration: SlotDuration
): {
  hasConflict: boolean;
  conflictingAppointment?: { date: string; time: string };
} => {
  const newDateTime = `${newDate}T${newTime}`;
  const newMinutes = timeToMinutes(newTime);
  
  for (const appointment of existingAppointments) {
    const appointmentDate = appointment.date.split('T')[0];
    
    // Only check conflicts on the same date
    if (appointmentDate === newDate) {
      const appointmentTime = new Date(appointment.date).toLocaleTimeString('pt-BR', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
      const appointmentMinutes = timeToMinutes(appointmentTime);
      
      // Check if times overlap considering slot duration
      const timeDiff = Math.abs(newMinutes - appointmentMinutes);
      if (timeDiff < slotDuration) {
        return {
          hasConflict: true,
          conflictingAppointment: appointment
        };
      }
    }
  }
  
  return { hasConflict: false };
};