import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { Calendar, Clock, Settings, CalendarDays, Plus, Edit, Trash2, Eye, User, MapPin, X, Check, ChevronLeft, ChevronRight } from 'lucide-react';
import { format, startOfWeek, endOfWeek, startOfMonth, endOfMonth, addDays, isSameDay, parseISO, addWeeks, subWeeks, addMonths, subMonths, startOfDay, endOfDay, eachDayOfInterval, getDay } from 'date-fns';
import { ptBR } from 'date-fns/locale';

type ScheduleSettings = {
  professional_id: number;
  work_days: number[];
  work_start_time: string;
  work_end_time: string;
  break_start_time: string;
  break_end_time: string;
  consultation_duration: number;
  has_scheduling_subscription: boolean;
};

type Appointment = {
  id: number;
  appointment_date: string;
  appointment_time: string;
  patient_name: string;
  patient_cpf: string;
  service_name: string;
  location_name: string;
  location_address: string;
  value: number;
  status: string;
  notes: string;
  consultation_duration: number;
};

type TimeSlot = {
  time: string;
  available: boolean;
  duration: number;
  appointment?: Appointment;
};

type Service = {
  id: number;
  name: string;
  base_price: number;
};

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  is_default: boolean;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
};

const SchedulingPage: React.FC = () => {
  const { user } = useAuth();
  const [currentDate, setCurrentDate] = useState(new Date());
  const [viewMode, setViewMode] = useState<'day' | 'week' | 'month'>('week');
  const [scheduleSettings, setScheduleSettings] = useState<ScheduleSettings | null>(null);
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [availableSlots, setAvailableSlots] = useState<TimeSlot[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [locations, setLocations] = useState<AttendanceLocation[]>([]);
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal states
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [showAppointmentModal, setShowAppointmentModal] = useState(false);
  const [showViewModal, setShowViewModal] = useState(false);
  const [appointmentModalMode, setAppointmentModalMode] = useState<'create' | 'edit'>('create');
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  const [selectedDate, setSelectedDate] = useState<string>('');
  const [selectedTime, setSelectedTime] = useState<string>('');
  
  // Settings form state
  const [settingsForm, setSettingsForm] = useState({
    work_days: [1, 2, 3, 4, 5],
    work_start_time: '08:00',
    work_end_time: '18:00',
    break_start_time: '12:00',
    break_end_time: '13:00',
    consultation_duration: 60
  });

  // Appointment form state
  const [appointmentForm, setAppointmentForm] = useState({
    patient_type: 'private' as 'private' | 'convenio',
    private_patient_id: '',
    client_cpf: '',
    client_id: null as number | null,
    dependent_id: null as number | null,
    service_id: '',
    location_id: '',
    notes: '',
    value: ''
  });

  // Client search state
  const [clientSearchResult, setClientSearchResult] = useState<any>(null);
  const [dependents, setDependents] = useState<any[]>([]);
  const [isSearching, setIsSearching] = useState(false);

  // Delete confirmation
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [appointmentToDelete, setAppointmentToDelete] = useState<Appointment | null>(null);

  // Get API URL
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }
    return "http://localhost:3001";
  };

  useEffect(() => {
    fetchInitialData();
  }, []);

  useEffect(() => {
    if (scheduleSettings) {
      fetchAppointments();
    }
  }, [currentDate, viewMode, scheduleSettings]);

  const fetchInitialData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Fetch schedule settings
      const settingsResponse = await fetch(`${apiUrl}/api/scheduling/settings`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (settingsResponse.ok) {
        const settings = await settingsResponse.json();
        setScheduleSettings(settings);
        setSettingsForm({
          work_days: settings.work_days || [1, 2, 3, 4, 5],
          work_start_time: settings.work_start_time || '08:00',
          work_end_time: settings.work_end_time || '18:00',
          break_start_time: settings.break_start_time || '12:00',
          break_end_time: settings.break_end_time || '13:00',
          consultation_duration: settings.consultation_duration || 60
        });
      }

      // Fetch services
      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (servicesResponse.ok) {
        const servicesData = await servicesResponse.json();
        setServices(servicesData);
      }

      // Fetch locations
      const locationsResponse = await fetch(`${apiUrl}/api/attendance-locations`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        setLocations(locationsData);
      }

      // Fetch private patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        setPrivatePatients(patientsData);
      }

    } catch (error) {
      console.error('Error fetching initial data:', error);
      setError('Erro ao carregar dados');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchAppointments = async () => {
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      let startDate, endDate;
      
      if (viewMode === 'day') {
        startDate = format(currentDate, 'yyyy-MM-dd');
        endDate = format(currentDate, 'yyyy-MM-dd');
      } else if (viewMode === 'week') {
        startDate = format(startOfWeek(currentDate, { weekStartsOn: 0 }), 'yyyy-MM-dd');
        endDate = format(endOfWeek(currentDate, { weekStartsOn: 0 }), 'yyyy-MM-dd');
      } else {
        startDate = format(startOfMonth(currentDate), 'yyyy-MM-dd');
        endDate = format(endOfMonth(currentDate), 'yyyy-MM-dd');
      }

      console.log('🔍 Fetching appointments from:', `${apiUrl}/api/appointments`);
      console.log('🔍 Date range:', { startDate, endDate });

      const response = await fetch(
        `${apiUrl}/api/scheduling/appointments?start_date=${startDate}&end_date=${endDate}`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      if (response.ok) {
        const data = await response.json();
        console.log('✅ Appointments received:', data);
        setAppointments(data);
      }
    } catch (error) {
      console.error('Error fetching appointments:', error);
    }
  };

  const fetchAvailableSlots = async (date: string) => {
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(
        `${apiUrl}/api/scheduling/available-slots?date=${date}`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      if (response.ok) {
        const data = await response.json();
        setAvailableSlots(data.available_slots || []);
      }
    } catch (error) {
      console.error('Error fetching available slots:', error);
    }
  };

  const searchClient = async () => {
    if (!appointmentForm.client_cpf) return;

    try {
      setIsSearching(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      const cleanCpf = appointmentForm.client_cpf.replace(/\D/g, '');

      // Search for dependent first
      const dependentResponse = await fetch(`${apiUrl}/api/dependents/lookup?cpf=${cleanCpf}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (dependentResponse.ok) {
        const dependentData = await dependentResponse.json();
        if (dependentData.client_subscription_status === 'active') {
          setClientSearchResult(dependentData);
          setAppointmentForm(prev => ({
            ...prev,
            client_id: dependentData.client_id,
            dependent_id: dependentData.id
          }));
          return;
        } else {
          setError('Dependente encontrado, mas o titular não possui assinatura ativa');
          return;
        }
      }

      // Search for client
      const clientResponse = await fetch(`${apiUrl}/api/clients/lookup?cpf=${cleanCpf}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (clientResponse.ok) {
        const clientData = await clientResponse.json();
        if (clientData.subscription_status === 'active') {
          setClientSearchResult(clientData);
          setAppointmentForm(prev => ({
            ...prev,
            client_id: clientData.id,
            dependent_id: null
          }));

          // Fetch dependents
          const dependentsResponse = await fetch(`${apiUrl}/api/dependents/${clientData.id}`, {
            headers: { 'Authorization': `Bearer ${token}` }
          });

          if (dependentsResponse.ok) {
            const dependentsData = await dependentsResponse.json();
            setDependents(dependentsData);
          }
        } else {
          setError('Cliente encontrado, mas não possui assinatura ativa');
        }
      } else {
        setError('Cliente não encontrado');
      }
    } catch (error) {
      setError('Erro ao buscar cliente');
    } finally {
      setIsSearching(false);
    }
  };

  const openAppointmentModal = (mode: 'create' | 'edit', date?: string, time?: string, appointment?: Appointment) => {
    setAppointmentModalMode(mode);
    
    if (mode === 'create') {
      setSelectedDate(date || format(currentDate, 'yyyy-MM-dd'));
      setSelectedTime(time || '');
      setAppointmentForm({
        patient_type: 'private',
        private_patient_id: '',
        client_cpf: '',
        client_id: null,
        dependent_id: null,
        service_id: '',
        location_id: locations.find(l => l.is_default)?.id.toString() || '',
        notes: '',
        value: ''
      });
      setClientSearchResult(null);
      setDependents([]);
      
      if (date) {
        fetchAvailableSlots(date);
      }
    } else if (mode === 'edit' && appointment) {
      setSelectedAppointment(appointment);
      setSelectedDate(appointment.appointment_date);
      setSelectedTime(appointment.appointment_time);
      // Set form data based on appointment
    }
    
    setShowAppointmentModal(true);
  };

  const closeAppointmentModal = () => {
    setShowAppointmentModal(false);
    setSelectedAppointment(null);
    setError('');
    setSuccess('');
  };

  const handleAppointmentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const appointmentData = {
        private_patient_id: appointmentForm.patient_type === 'private' ? parseInt(appointmentForm.private_patient_id) : null,
        client_id: appointmentForm.patient_type === 'convenio' && !appointmentForm.dependent_id ? appointmentForm.client_id : null,
        dependent_id: appointmentForm.patient_type === 'convenio' ? appointmentForm.dependent_id : null,
        service_id: parseInt(appointmentForm.service_id),
        appointment_date: selectedDate,
        appointment_time: selectedTime,
        location_id: appointmentForm.location_id ? parseInt(appointmentForm.location_id) : null,
        notes: appointmentForm.notes,
        value: parseFloat(appointmentForm.value)
      };

      const response = await fetch(`${apiUrl}/api/scheduling/appointments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(appointmentData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao criar agendamento');
      }

      setSuccess('Agendamento criado com sucesso!');
      await fetchAppointments();
      
      setTimeout(() => {
        closeAppointmentModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao criar agendamento');
    }
  };

  const handleSettingsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/scheduling/settings`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(settingsForm)
      });

      if (!response.ok) {
        throw new Error('Erro ao salvar configurações');
      }

      await fetchInitialData();
      setShowSettingsModal(false);
      setSuccess('Configurações salvas com sucesso!');
    } catch (error) {
      console.error('Error saving settings:', error);
      setError('Erro ao salvar configurações');
    }
  };

  const confirmDelete = (appointment: Appointment) => {
    setAppointmentToDelete(appointment);
    setShowDeleteConfirm(true);
  };

  const deleteAppointment = async () => {
    if (!appointmentToDelete) return;

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/scheduling/appointments/${appointmentToDelete.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        throw new Error('Erro ao excluir agendamento');
      }

      await fetchAppointments();
      setSuccess('Agendamento excluído com sucesso!');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao excluir agendamento');
    } finally {
      setAppointmentToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const navigateDate = (direction: 'prev' | 'next') => {
    if (viewMode === 'day') {
      setCurrentDate(prev => addDays(prev, direction === 'next' ? 1 : -1));
    } else if (viewMode === 'week') {
      setCurrentDate(prev => direction === 'next' ? addWeeks(prev, 1) : subWeeks(prev, 1));
    } else {
      setCurrentDate(prev => direction === 'next' ? addMonths(prev, 1) : subMonths(prev, 1));
    }
  };

  const generateTimeSlots = () => {
    if (!scheduleSettings) return [];

    const slots = [];
    const startTime = new Date(`2000-01-01T${scheduleSettings.work_start_time}`);
    const endTime = new Date(`2000-01-01T${scheduleSettings.work_end_time}`);
    const breakStart = new Date(`2000-01-01T${scheduleSettings.break_start_time}`);
    const breakEnd = new Date(`2000-01-01T${scheduleSettings.break_end_time}`);
    const duration = scheduleSettings.consultation_duration;

    let currentTime = new Date(startTime);

    while (currentTime < endTime) {
      const timeString = currentTime.toTimeString().slice(0, 5);
      const slotEndTime = new Date(currentTime.getTime() + duration * 60000);

      // Check if slot is in break time
      const isInBreak = currentTime >= breakStart && currentTime < breakEnd;

      if (!isInBreak && slotEndTime <= endTime) {
        slots.push({
          time: timeString,
          available: true,
          duration: duration
        });
      }

      currentTime = new Date(currentTime.getTime() + duration * 60000);
    }

    return slots;
  };

  const getAppointmentForSlot = (date: string, time: string) => {
    return appointments.find(apt => 
      apt.appointment_date === date && 
      apt.appointment_time === time
    );
  };

  // Check if a time slot is occupied
  const isSlotOccupied = (date: Date, time: string) => {
    const dateStr = format(date, 'yyyy-MM-dd');
    console.log('🔍 Checking slot:', { dateStr, time });
    console.log('🔍 Available appointments:', appointments.map(a => ({ 
      date: a.appointment_date, 
      time: a.appointment_time,
      patient: a.patient_name 
    })));
    
    return appointments.some(apt => 
      apt.appointment_date === dateStr && 
      apt.appointment_time === time
    );
  };

  // Get appointment for a specific slot
  const getSlotAppointment = (date: Date, time: string) => {
    const dateStr = format(date, 'yyyy-MM-dd');
    return appointments.find(apt => 
      apt.appointment_date === dateStr && 
      apt.appointment_time === time
    );
  };

  const renderDayView = () => {
    const dateString = format(currentDate, 'yyyy-MM-dd');
    const dayOfWeek = getDay(currentDate);
    const isWorkingDay = scheduleSettings?.work_days.includes(dayOfWeek);

    if (!isWorkingDay) {
      return (
        <div className="text-center py-12 bg-gray-50 rounded-lg">
          <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">Dia não útil</h3>
          <p className="text-gray-600">Este dia não está configurado como dia de trabalho.</p>
        </div>
      );
    }

    const timeSlots = generateTimeSlots();

    return (
      <div className="space-y-2">
        {timeSlots.map((slot) => {
          const appointment = getAppointmentForSlot(dateString, slot.time);
          
          return (
            <div
              key={slot.time}
              className={`p-4 rounded-lg border-2 transition-all cursor-pointer ${
                appointment
                  ? 'border-red-200 bg-red-50 hover:border-red-300'
                  : 'border-gray-200 bg-white hover:border-red-200 hover:bg-red-25'
              }`}
              onClick={() => {
                if (appointment) {
                  setSelectedAppointment(appointment);
                  setShowViewModal(true);
                } else {
                  openAppointmentModal('create', dateString, slot.time);
                }
              }}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <Clock className="h-4 w-4 text-gray-500 mr-2" />
                  <span className="font-medium">{slot.time}</span>
                  <span className="text-sm text-gray-500 ml-2">
                    ({slot.duration} min)
                  </span>
                </div>
                
                {appointment ? (
                  <div className="flex items-center space-x-2">
                    <span className="text-sm font-medium text-red-700">
                      {appointment.patient_name}
                    </span>
                    <div className="flex space-x-1">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAppointment(appointment);
                          setShowViewModal(true);
                        }}
                        className="p-1 text-blue-600 hover:bg-blue-100 rounded"
                      >
                        <Eye className="h-3 w-3" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openAppointmentModal('edit', dateString, slot.time, appointment);
                        }}
                        className="p-1 text-green-600 hover:bg-green-100 rounded"
                      >
                        <Edit className="h-3 w-3" />
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          confirmDelete(appointment);
                        }}
                        className="p-1 text-red-600 hover:bg-red-100 rounded"
                      >
                        <Trash2 className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                ) : (
                  <span className="text-sm text-gray-500">Disponível</span>
                )}
              </div>
              
              {appointment && (
                <div className="mt-2 text-sm text-gray-600">
                  <p>{appointment.service_name}</p>
                  {appointment.location_name && (
                    <p className="flex items-center">
                      <MapPin className="h-3 w-3 mr-1" />
                      {appointment.location_name}
                    </p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  const renderWeekView = () => {
    const weekStart = startOfWeek(currentDate, { weekStartsOn: 0 });
    const weekDays = eachDayOfInterval({
      start: weekStart,
      end: endOfWeek(currentDate, { weekStartsOn: 0 })
    });

    return (
      <div className="grid grid-cols-7 gap-2">
        {weekDays.map((day) => {
          const dateString = format(day, 'yyyy-MM-dd');
          const dayOfWeek = getDay(day);
          const isWorkingDay = scheduleSettings?.work_days.includes(dayOfWeek);
          const dayAppointments = appointments.filter(apt => apt.appointment_date === dateString);

          return (
            <div key={dateString} className="border border-gray-200 rounded-lg p-2 min-h-[200px]">
              <div className="text-center mb-2">
                <div className="text-xs text-gray-500">
                  {format(day, 'EEE', { locale: ptBR })}
                </div>
                <div className={`text-sm font-medium ${
                  isSameDay(day, new Date()) ? 'text-red-600' : 'text-gray-900'
                }`}>
                  {format(day, 'd')}
                </div>
              </div>

              {!isWorkingDay ? (
                <div className="text-center text-xs text-gray-400 mt-4">
                  Não útil
                </div>
              ) : (
                <div className="space-y-1">
                  {dayAppointments.map((appointment) => (
                    <div
                      key={appointment.id}
                      className="bg-red-100 text-red-800 p-1 rounded text-xs cursor-pointer hover:bg-red-200"
                      onClick={() => {
                        setSelectedAppointment(appointment);
                        setShowViewModal(true);
                      }}
                    >
                      <div className="font-medium">{appointment.appointment_time.slice(0, 5)}</div>
                      <div className="truncate">{appointment.patient_name}</div>
                    </div>
                  ))}
                  
                  {dayAppointments.length === 0 && (
                    <button
                      onClick={() => openAppointmentModal('create', dateString)}
                      className="w-full text-xs text-gray-500 hover:text-red-600 hover:bg-red-50 p-1 rounded transition-colors"
                    >
                      + Agendar
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  };

  const renderMonthView = () => {
    const monthStart = startOfMonth(currentDate);
    const monthEnd = endOfMonth(currentDate);
    const calendarStart = startOfWeek(monthStart, { weekStartsOn: 0 });
    const calendarEnd = endOfWeek(monthEnd, { weekStartsOn: 0 });
    
    const calendarDays = eachDayOfInterval({
      start: calendarStart,
      end: calendarEnd
    });

    return (
      <div>
        {/* Week headers */}
        <div className="grid grid-cols-7 gap-2 mb-2">
          {['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'].map((day) => (
            <div key={day} className="text-center text-sm font-medium text-gray-700 py-2">
              {day}
            </div>
          ))}
        </div>

        {/* Calendar grid */}
        <div className="grid grid-cols-7 gap-2">
          {calendarDays.map((day) => {
            const dateString = format(day, 'yyyy-MM-dd');
            const dayOfWeek = getDay(day);
            const isWorkingDay = scheduleSettings?.work_days.includes(dayOfWeek);
            const dayAppointments = appointments.filter(apt => apt.appointment_date === dateString);
            const isCurrentMonth = day >= monthStart && day <= monthEnd;
            const isToday = isSameDay(day, new Date());

            return (
              <div
                key={dateString}
                className={`border border-gray-200 rounded-lg p-2 min-h-[100px] cursor-pointer hover:border-red-200 ${
                  !isCurrentMonth ? 'bg-gray-50 opacity-50' : 'bg-white'
                } ${isToday ? 'border-red-300 bg-red-25' : ''}`}
                onClick={() => {
                  setCurrentDate(day);
                  setViewMode('day');
                }}
              >
                <div className={`text-sm font-medium mb-1 ${
                  isToday ? 'text-red-600' : isCurrentMonth ? 'text-gray-900' : 'text-gray-400'
                }`}>
                  {format(day, 'd')}
                </div>

                {isWorkingDay && isCurrentMonth && (
                  <div className="space-y-1">
                    {dayAppointments.slice(0, 2).map((appointment) => (
                      <div
                        key={appointment.id}
                        className="bg-red-100 text-red-800 p-1 rounded text-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAppointment(appointment);
                          setShowViewModal(true);
                        }}
                      >
                        <div className="font-medium">{appointment.appointment_time.slice(0, 5)}</div>
                        <div className="truncate">{appointment.patient_name}</div>
                      </div>
                    ))}
                    
                    {dayAppointments.length > 2 && (
                      <div className="text-xs text-gray-500 text-center">
                        +{dayAppointments.length - 2} mais
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL'
    }).format(value);
  };

  const formatTime = (time: string) => {
    return time.slice(0, 5);
  };

  const getDayName = (dayNumber: number) => {
    const days = ['Domingo', 'Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado'];
    return days[dayNumber];
  };

  const handleWorkDayChange = (day: number, checked: boolean) => {
    if (checked) {
      setSettingsForm(prev => ({
        ...prev,
        work_days: [...prev.work_days, day].sort()
      }));
    } else {
      setSettingsForm(prev => ({
        ...prev,
        work_days: prev.work_days.filter(d => d !== day)
      }));
    }
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    setAppointmentForm(prev => ({ ...prev, client_cpf: limitedValue }));
  };

  const formattedCpf = appointmentForm.client_cpf
    ? appointmentForm.client_cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')
    : '';

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
        <p className="text-gray-600">Carregando agenda...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda Profissional</h1>
          <p className="text-gray-600">Gerencie seus agendamentos e horários</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <button
            onClick={() => setShowSettingsModal(true)}
            className="btn btn-outline flex items-center"
          >
            <Settings className="h-5 w-5 mr-2" />
            Configurações
          </button>
          
          <button
            onClick={() => openAppointmentModal('create')}
            className="btn btn-primary flex items-center"
          >
            <Plus className="h-5 w-5 mr-2" />
            Novo Agendamento
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6">
          {success}
        </div>
      )}

      {/* Calendar Controls */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setViewMode('day')}
            className={`px-4 py-2 rounded-lg transition-colors ${
              viewMode === 'day' 
                ? 'bg-red-600 text-white' 
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Dia
          </button>
          <button
            onClick={() => setViewMode('week')}
            className={`px-4 py-2 rounded-lg transition-colors ${
              viewMode === 'week' 
                ? 'bg-red-600 text-white' 
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Semana
          </button>
          <button
            onClick={() => setViewMode('month')}
            className={`px-4 py-2 rounded-lg transition-colors ${
              viewMode === 'month' 
                ? 'bg-red-600 text-white' 
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Mês
          </button>
        </div>

        <div className="flex items-center space-x-4">
          <button
            onClick={() => navigateDate('prev')}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
          
          <h2 className="text-lg font-semibold min-w-[200px] text-center">
            {viewMode === 'day' && format(currentDate, "dd 'de' MMMM 'de' yyyy", { locale: ptBR })}
            {viewMode === 'week' && `${format(startOfWeek(currentDate, { weekStartsOn: 0 }), 'dd/MM')} - ${format(endOfWeek(currentDate, { weekStartsOn: 0 }), 'dd/MM/yyyy')}`}
            {viewMode === 'month' && format(currentDate, "MMMM 'de' yyyy", { locale: ptBR })}
          </h2>
          
          <button
            onClick={() => navigateDate('next')}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        </div>

        <button
          onClick={() => setCurrentDate(new Date())}
          className="btn btn-secondary"
        >
          Hoje
        </button>
      </div>

      {/* Calendar View */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        {viewMode === 'day' && renderDayView()}
        {viewMode === 'week' && renderWeekView()}
        {viewMode === 'month' && renderMonthView()}
      </div>

      {/* Settings Modal */}
      {showSettingsModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">Configurações da Agenda</h2>
            </div>
            
            <form onSubmit={handleSettingsSubmit} className="p-6 space-y-6">
              <div>
                <h3 className="text-lg font-semibold mb-4">Dias de Trabalho</h3>
                <div className="grid grid-cols-7 gap-2">
                  {[0, 1, 2, 3, 4, 5, 6].map((day) => (
                    <label key={day} className="flex flex-col items-center">
                      <input
                        type="checkbox"
                        checked={settingsForm.work_days.includes(day)}
                        onChange={(e) => handleWorkDayChange(day, e.target.checked)}
                        className="mb-1"
                      />
                      <span className="text-xs text-center">{getDayName(day)}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Início do Expediente
                  </label>
                  <input
                    type="time"
                    value={settingsForm.work_start_time}
                    onChange={(e) => setSettingsForm(prev => ({ ...prev, work_start_time: e.target.value }))}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Fim do Expediente
                  </label>
                  <input
                    type="time"
                    value={settingsForm.work_end_time}
                    onChange={(e) => setSettingsForm(prev => ({ ...prev, work_end_time: e.target.value }))}
                    className="input"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Início do Intervalo
                  </label>
                  <input
                    type="time"
                    value={settingsForm.break_start_time}
                    onChange={(e) => setSettingsForm(prev => ({ ...prev, break_start_time: e.target.value }))}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Fim do Intervalo
                  </label>
                  <input
                    type="time"
                    value={settingsForm.break_end_time}
                    onChange={(e) => setSettingsForm(prev => ({ ...prev, break_end_time: e.target.value }))}
                    className="input"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Duração da Consulta (minutos)
                </label>
                <select
                  value={settingsForm.consultation_duration}
                  onChange={(e) => setSettingsForm(prev => ({ ...prev, consultation_duration: parseInt(e.target.value) }))}
                  className="input"
                >
                  <option value={15}>15 minutos</option>
                  <option value={30}>30 minutos</option>
                  <option value={45}>45 minutos</option>
                  <option value={60}>1 hora</option>
                  <option value={90}>1h 30min</option>
                  <option value={120}>2 horas</option>
                </select>
              </div>

              <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={() => setShowSettingsModal(false)}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  Salvar Configurações
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Appointment Modal */}
      {showAppointmentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {appointmentModalMode === 'create' ? 'Novo Agendamento' : 'Editar Agendamento'}
              </h2>
            </div>

            <form onSubmit={handleAppointmentSubmit} className="p-6 space-y-6">
              {/* Date and Time */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data *
                  </label>
                  <input
                    type="date"
                    value={selectedDate}
                    onChange={(e) => {
                      setSelectedDate(e.target.value);
                      fetchAvailableSlots(e.target.value);
                    }}
                    className="input"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Horário *
                  </label>
                  <select
                    value={selectedTime}
                    onChange={(e) => setSelectedTime(e.target.value)}
                    className="input"
                    required
                  >
                    <option value="">Selecione um horário</option>
                    {availableSlots.map((slot) => (
                      <option key={slot.time} value={slot.time}>
                        {slot.time} ({slot.duration} min)
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Patient Type Selection */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-3">
                  Tipo de Paciente *
                </label>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    type="button"
                    onClick={() => setAppointmentForm(prev => ({ 
                      ...prev, 
                      patient_type: 'private',
                      client_cpf: '',
                      client_id: null,
                      dependent_id: null
                    }))}
                    className={`p-3 rounded-lg border-2 transition-all ${
                      appointmentForm.patient_type === 'private'
                        ? 'border-red-600 bg-red-50 text-red-700'
                        : 'border-gray-200 bg-white text-gray-700 hover:border-gray-300'
                    }`}
                  >
                    <User className="h-6 w-6 mx-auto mb-1" />
                    <div className="text-sm font-medium">Particular</div>
                  </button>
                  
                  <button
                    type="button"
                    onClick={() => setAppointmentForm(prev => ({ 
                      ...prev, 
                      patient_type: 'convenio',
                      private_patient_id: ''
                    }))}
                    className={`p-3 rounded-lg border-2 transition-all ${
                      appointmentForm.patient_type === 'convenio'
                        ? 'border-red-600 bg-red-50 text-red-700'
                        : 'border-gray-200 bg-white text-gray-700 hover:border-gray-300'
                    }`}
                  >
                    <CalendarDays className="h-6 w-6 mx-auto mb-1" />
                    <div className="text-sm font-medium">Convênio</div>
                  </button>
                </div>
              </div>

              {/* Patient Selection */}
              {appointmentForm.patient_type === 'private' ? (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Paciente Particular *
                  </label>
                  <select
                    value={appointmentForm.private_patient_id}
                    onChange={(e) => setAppointmentForm(prev => ({ ...prev, private_patient_id: e.target.value }))}
                    className="input"
                    required
                  >
                    <option value="">Selecione um paciente</option>
                    {privatePatients.map((patient) => (
                      <option key={patient.id} value={patient.id}>
                        {patient.name} - {patient.cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')}
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    CPF do Cliente/Dependente *
                  </label>
                  <div className="flex space-x-2">
                    <input
                      type="text"
                      value={formattedCpf}
                      onChange={(e) => formatCpf(e.target.value)}
                      placeholder="000.000.000-00"
                      className="input flex-1"
                    />
                    <button
                      type="button"
                      onClick={searchClient}
                      className="btn btn-outline"
                      disabled={isSearching}
                    >
                      {isSearching ? 'Buscando...' : 'Buscar'}
                    </button>
                  </div>

                  {clientSearchResult && (
                    <div className="mt-3 p-3 bg-green-50 rounded-lg">
                      <p className="text-green-700">
                        <strong>Encontrado:</strong> {clientSearchResult.name}
                      </p>
                      
                      {dependents.length > 0 && (
                        <div className="mt-2">
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Dependente (opcional)
                          </label>
                          <select
                            value={appointmentForm.dependent_id || ''}
                            onChange={(e) => setAppointmentForm(prev => ({ 
                              ...prev, 
                              dependent_id: e.target.value ? parseInt(e.target.value) : null 
                            }))}
                            className="input"
                          >
                            <option value="">Agendamento para o titular</option>
                            {dependents.map((dependent) => (
                              <option key={dependent.id} value={dependent.id}>
                                {dependent.name}
                              </option>
                            ))}
                          </select>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Service and Location */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Serviço *
                  </label>
                  <select
                    value={appointmentForm.service_id}
                    onChange={(e) => {
                      const serviceId = e.target.value;
                      const service = services.find(s => s.id.toString() === serviceId);
                      setAppointmentForm(prev => ({ 
                        ...prev, 
                        service_id: serviceId,
                        value: service ? service.base_price.toString() : ''
                      }));
                    }}
                    className="input"
                    required
                  >
                    <option value="">Selecione um serviço</option>
                    {services.map((service) => (
                      <option key={service.id} value={service.id}>
                        {service.name} - {formatCurrency(service.base_price)}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Local de Atendimento
                  </label>
                  <select
                    value={appointmentForm.location_id}
                    onChange={(e) => setAppointmentForm(prev => ({ ...prev, location_id: e.target.value }))}
                    className="input"
                  >
                    <option value="">Selecione um local</option>
                    {locations.map((location) => (
                      <option key={location.id} value={location.id}>
                        {location.name} {location.is_default && '(Padrão)'}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Value and Notes */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Valor (R$) *
                  </label>
                  <input
                    type="number"
                    min="0"
                    step="0.01"
                    value={appointmentForm.value}
                    onChange={(e) => setAppointmentForm(prev => ({ ...prev, value: e.target.value }))}
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Observações
                  </label>
                  <textarea
                    value={appointmentForm.notes}
                    onChange={(e) => setAppointmentForm(prev => ({ ...prev, notes: e.target.value }))}
                    className="input min-h-[80px]"
                    placeholder="Observações sobre o agendamento..."
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeAppointmentModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {appointmentModalMode === 'create' ? 'Criar Agendamento' : 'Salvar Alterações'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View Appointment Modal */}
      {showViewModal && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl">
            <div className="p-6 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-xl font-bold">Detalhes do Agendamento</h2>
              <button
                onClick={() => setShowViewModal(false)}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="font-semibold text-gray-900">Data</h3>
                  <p className="text-gray-700">
                    {format(parseISO(selectedAppointment.appointment_date), "dd 'de' MMMM 'de' yyyy", { locale: ptBR })}
                  </p>
                </div>
                <div>
                  <h3 className="font-semibold text-gray-900">Horário</h3>
                  <p className="text-gray-700">
                    {formatTime(selectedAppointment.appointment_time)} 
                    Para criar novos agendamentos, use o menu "Registrar Consulta". 
                    Total de agendamentos: {appointments.length}
                  </p>
                </div>
              </div>

              <div>
                <h3 className="font-semibold text-gray-900">Paciente</h3>
                <p className="text-gray-700">{selectedAppointment.patient_name}</p>
                <p className="text-sm text-gray-500">
                  CPF: {selectedAppointment.patient_cpf?.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')}
                </p>
              </div>

              <div>
                <h3 className="font-semibold text-gray-900">Serviço</h3>
                <p className="text-gray-700">{selectedAppointment.service_name}</p>
              </div>

              {selectedAppointment.location_name && (
                <div>
                  <h3 className="font-semibold text-gray-900">Local</h3>
                  <p className="text-gray-700">{selectedAppointment.location_name}</p>
                  {selectedAppointment.location_address && (
                    <p className="text-sm text-gray-500">{selectedAppointment.location_address}</p>
                  )}
                </div>
              )}

              <div>
                <h3 className="font-semibold text-gray-900">Valor</h3>
                <p className="text-gray-700 font-medium text-lg">
                  {formatCurrency(selectedAppointment.value)}
                </p>
              </div>

              {selectedAppointment.notes && (
                <div>
                  <h3 className="font-semibold text-gray-900">Observações</h3>
                  <p className="text-gray-700">{selectedAppointment.notes}</p>
                </div>
              )}

              <div className="flex justify-end space-x-3 pt-6 border-t border-gray-200">
                <button
                  onClick={() => setShowViewModal(false)}
                  className="btn btn-secondary"
                >
                  Fechar
                </button>
                <button
                  onClick={() => {
                    setShowViewModal(false);
                    openAppointmentModal('edit', selectedAppointment.appointment_date, selectedAppointment.appointment_time, selectedAppointment);
                  }}
                  className="btn btn-primary flex items-center"
                >
                  <Edit className="h-4 w-4 mr-2" />
                  Editar
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && appointmentToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir o agendamento de{' '}
              <strong>{appointmentToDelete.patient_name}</strong> para{' '}
              {format(parseISO(appointmentToDelete.appointment_date), "dd/MM/yyyy")} às{' '}
              {formatTime(appointmentToDelete.appointment_time)}?
            </p>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={() => {
                  setAppointmentToDelete(null);
                  setShowDeleteConfirm(false);
                }}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={deleteAppointment}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Check className="h-4 w-4 mr-2" />
                Confirmar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;