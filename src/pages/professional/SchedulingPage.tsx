import React, { useState, useEffect } from 'react';
import { Calendar, Plus, Edit, Trash2, Clock, MapPin, User, ChevronLeft, ChevronRight, Eye, X, Check, AlertCircle } from 'lucide-react';
import { format, startOfMonth, endOfMonth, startOfWeek, endOfWeek, addDays, isSameMonth, isSameDay, addMonths, subMonths, addWeeks, subWeeks } from 'date-fns';
import { ptBR } from 'date-fns/locale';

type Appointment = {
  id: number;
  patient_name: string;
  patient_cpf: string;
  service_name: string;
  appointment_date: string;
  appointment_time: string;
  location_name: string;
  location_address: string;
  notes: string;
  value: number;
  status: string;
  private_patient_id?: number;
  client_id?: number;
  dependent_id?: number;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
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

type ViewMode = 'month' | 'week' | 'day';

const SchedulingPage: React.FC = () => {
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [locations, setLocations] = useState<AttendanceLocation[]>([]);
  
  // Calendar state
  const [currentDate, setCurrentDate] = useState(new Date());
  const [viewMode, setViewMode] = useState<ViewMode>('month');
  
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  
  // Form state
  const [formData, setFormData] = useState({
    private_patient_id: '',
    service_id: '',
    appointment_date: '',
    appointment_time: '',
    location_id: '',
    notes: '',
    value: ''
  });
  
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

  // Get date range based on view mode
  const getDateRange = () => {
    switch (viewMode) {
      case 'month':
        return {
          start: format(startOfMonth(currentDate), 'yyyy-MM-dd'),
          end: format(endOfMonth(currentDate), 'yyyy-MM-dd')
        };
      case 'week':
        return {
          start: format(startOfWeek(currentDate, { locale: ptBR }), 'yyyy-MM-dd'),
          end: format(endOfWeek(currentDate, { locale: ptBR }), 'yyyy-MM-dd')
        };
      case 'day':
        return {
          start: format(currentDate, 'yyyy-MM-dd'),
          end: format(currentDate, 'yyyy-MM-dd')
        };
    }
  };

  // Fetch all data
  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      const dateRange = getDateRange();

      console.log('🔄 Fetching scheduling data...');
      console.log('📅 Date range:', dateRange);
      console.log('🌐 API URL:', apiUrl);

      // Fetch appointments with date filter
      const appointmentsUrl = `${apiUrl}/api/scheduling/appointments?start_date=${dateRange.start}&end_date=${dateRange.end}`;
      console.log('📡 Fetching appointments from:', appointmentsUrl);

      const appointmentsResponse = await fetch(appointmentsUrl, {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      console.log('📡 Appointments response status:', appointmentsResponse.status);

      if (!appointmentsResponse.ok) {
        const errorData = await appointmentsResponse.json();
        console.error('❌ Appointments error:', errorData);
        throw new Error(errorData.message || 'Erro ao carregar agendamentos');
      }

      const appointmentsData = await appointmentsResponse.json();
      console.log('✅ Appointments loaded:', appointmentsData.length, 'items');
      console.log('📋 Sample appointment:', appointmentsData[0]);
      setAppointments(appointmentsData);

      // Fetch private patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        console.log('✅ Private patients loaded:', patientsData.length, 'items');
        setPrivatePatients(patientsData);
      }

      // Fetch services
      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (servicesResponse.ok) {
        const servicesData = await servicesResponse.json();
        console.log('✅ Services loaded:', servicesData.length, 'items');
        setServices(servicesData);
      }

      // Fetch locations
      const locationsResponse = await fetch(`${apiUrl}/api/attendance-locations`, {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        console.log('✅ Locations loaded:', locationsData.length, 'items');
        setLocations(locationsData);
      }

    } catch (error) {
      console.error('❌ Error fetching data:', error);
      setError(error instanceof Error ? error.message : 'Não foi possível carregar os dados da agenda');
    } finally {
      setIsLoading(false);
    }
  };

  // Load data when component mounts or date/view changes
  useEffect(() => {
    fetchData();
  }, [currentDate, viewMode]);

  // Status colors and text
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'scheduled':
        return 'bg-blue-500 border-blue-600 text-white';
      case 'completed':
        return 'bg-green-500 border-green-600 text-white';
      case 'cancelled':
        return 'bg-red-500 border-red-600 text-white';
      case 'no_show':
        return 'bg-yellow-500 border-yellow-600 text-white';
      default:
        return 'bg-gray-500 border-gray-600 text-white';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'scheduled':
        return 'Agendado';
      case 'completed':
        return 'Realizado';
      case 'cancelled':
        return 'Cancelado';
      case 'no_show':
        return 'Faltou';
      default:
        return status;
    }
  };

  // Get appointments for specific date
  const getAppointmentsForDate = (date: Date) => {
    const dateStr = format(date, 'yyyy-MM-dd');
    return appointments.filter(apt => apt.appointment_date === dateStr);
  };

  // Calendar navigation
  const navigateCalendar = (direction: 'prev' | 'next') => {
    switch (viewMode) {
      case 'month':
        setCurrentDate(direction === 'next' ? addMonths(currentDate, 1) : subMonths(currentDate, 1));
        break;
      case 'week':
        setCurrentDate(direction === 'next' ? addWeeks(currentDate, 1) : subWeeks(currentDate, 1));
        break;
      case 'day':
        setCurrentDate(direction === 'next' ? addDays(currentDate, 1) : addDays(currentDate, -1));
        break;
    }
  };

  // Modal functions
  const openCreateModal = (date?: Date) => {
    console.log('🔄 Opening create modal for date:', date);
    
    setModalMode('create');
    setFormData({
      private_patient_id: '',
      service_id: '',
      appointment_date: date ? format(date, 'yyyy-MM-dd') : '',
      appointment_time: '',
      location_id: locations.find(loc => loc.is_default)?.id.toString() || '',
      notes: '',
      value: ''
    });
    setSelectedAppointment(null);
    setIsModalOpen(true);
  };

  const openEditModal = (appointment: Appointment) => {
    console.log('🔄 Opening edit modal for appointment:', appointment);
    
    setModalMode('edit');
    setFormData({
      private_patient_id: appointment.private_patient_id?.toString() || '',
      service_id: '',
      appointment_date: appointment.appointment_date,
      appointment_time: appointment.appointment_time,
      location_id: '',
      notes: appointment.notes || '',
      value: appointment.value.toString()
    });
    setSelectedAppointment(appointment);
    setIsModalOpen(true);
  };

  const openDetailModal = (appointment: Appointment) => {
    console.log('🔄 Opening detail modal for appointment:', appointment);
    setSelectedAppointment(appointment);
    setIsDetailModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setIsDetailModalOpen(false);
    setError('');
    setSuccess('');
  };

  // Form handlers
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const serviceId = e.target.value;
    setFormData(prev => ({ ...prev, service_id: serviceId }));
    
    const selectedService = services.find(s => s.id.toString() === serviceId);
    if (selectedService) {
      setFormData(prev => ({ ...prev, value: selectedService.base_price.toString() }));
    }
  };

  // Submit form
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    console.log('🔄 Submitting appointment form:', formData);

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const url = modalMode === 'create' 
        ? `${apiUrl}/api/scheduling/appointments`
        : `${apiUrl}/api/scheduling/appointments/${selectedAppointment?.id}`;

      const method = modalMode === 'create' ? 'POST' : 'PUT';

      const requestBody = {
        private_patient_id: formData.private_patient_id ? parseInt(formData.private_patient_id) : null,
        service_id: parseInt(formData.service_id),
        appointment_date: formData.appointment_date,
        appointment_time: formData.appointment_time,
        location_id: formData.location_id ? parseInt(formData.location_id) : null,
        notes: formData.notes,
        value: parseFloat(formData.value)
      };

      console.log('📡 Sending request:', { method, url, body: requestBody });

      const response = await fetch(url, {
        method,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      console.log('📡 Response status:', response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error('❌ Error response:', errorData);
        throw new Error(errorData.message || 'Erro ao salvar agendamento');
      }

      const responseData = await response.json();
      console.log('✅ Appointment saved:', responseData);

      setSuccess(modalMode === 'create' ? 'Agendamento criado com sucesso!' : 'Agendamento atualizado com sucesso!');
      
      // Refresh data immediately
      await fetchData();

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      console.error('❌ Error in handleSubmit:', error);
      setError(error instanceof Error ? error.message : 'Erro ao salvar agendamento');
    }
  };

  // Delete appointment
  const confirmDelete = (appointment: Appointment) => {
    setAppointmentToDelete(appointment);
    setShowDeleteConfirm(true);
  };

  const cancelDelete = () => {
    setAppointmentToDelete(null);
    setShowDeleteConfirm(false);
  };

  const deleteAppointment = async () => {
    if (!appointmentToDelete) return;

    try {
      console.log('🗑️ Deleting appointment:', appointmentToDelete.id);
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/scheduling/appointments/${appointmentToDelete.id}`, {
        method: 'DELETE',
        headers: { 
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      console.log('📡 Delete response status:', response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error('❌ Delete error:', errorData);
        throw new Error(errorData.message || 'Erro ao excluir agendamento');
      }

      console.log('✅ Appointment deleted successfully');
      
      // Refresh data immediately
      await fetchData();
      setSuccess('Agendamento excluído com sucesso!');
    } catch (error) {
      console.error('❌ Error in deleteAppointment:', error);
      setError(error instanceof Error ? error.message : 'Erro ao excluir agendamento');
    } finally {
      setAppointmentToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  // Utility functions
  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };

  const formatTime = (timeString: string) => {
    return timeString.slice(0, 5);
  };

  const getViewTitle = () => {
    switch (viewMode) {
      case 'month':
        return format(currentDate, "MMMM 'de' yyyy", { locale: ptBR });
      case 'week':
        const weekStart = startOfWeek(currentDate, { locale: ptBR });
        const weekEnd = endOfWeek(currentDate, { locale: ptBR });
        return `${format(weekStart, 'd MMM', { locale: ptBR })} - ${format(weekEnd, 'd MMM yyyy', { locale: ptBR })}`;
      case 'day':
        return format(currentDate, "EEEE, d 'de' MMMM 'de' yyyy", { locale: ptBR });
    }
  };

  // Render Month View
  const renderMonthView = () => {
    const monthStart = startOfMonth(currentDate);
    const monthEnd = endOfMonth(monthStart);
    const startDate = startOfWeek(monthStart, { locale: ptBR });
    const endDate = endOfWeek(monthEnd, { locale: ptBR });

    const rows = [];
    let days = [];
    let day = startDate;

    while (day <= endDate) {
      for (let i = 0; i < 7; i++) {
        const cloneDay = day;
        const dayAppointments = getAppointmentsForDate(day);
        
        days.push(
          <div
            key={day.toString()}
            className={`min-h-[120px] border border-gray-200 p-2 cursor-pointer hover:bg-gray-50 transition-colors ${
              !isSameMonth(day, monthStart) ? 'bg-gray-100 text-gray-400' : 'bg-white'
            } ${isSameDay(day, new Date()) ? 'bg-blue-50 border-blue-300' : ''}`}
            onClick={() => openCreateModal(cloneDay)}
          >
            <div className="flex justify-between items-start mb-2">
              <span className={`text-sm font-medium ${
                isSameDay(day, new Date()) ? 'text-blue-600' : 'text-gray-900'
              }`}>
                {format(day, 'd')}
              </span>
              {dayAppointments.length > 0 && (
                <span className="bg-red-100 text-red-800 text-xs px-1.5 py-0.5 rounded-full">
                  {dayAppointments.length}
                </span>
              )}
            </div>
            
            <div className="space-y-1">
              {dayAppointments.slice(0, 3).map((appointment) => (
                <div
                  key={appointment.id}
                  className={`text-xs p-1.5 rounded border-l-2 cursor-pointer hover:opacity-80 ${getStatusColor(appointment.status)}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    openDetailModal(appointment);
                  }}
                >
                  <div className="font-medium truncate">
                    {formatTime(appointment.appointment_time)} - {appointment.patient_name}
                  </div>
                  <div className="truncate opacity-90">
                    {appointment.service_name}
                  </div>
                </div>
              ))}
              {dayAppointments.length > 3 && (
                <div className="text-xs text-gray-500 text-center">
                  +{dayAppointments.length - 3} mais
                </div>
              )}
            </div>
          </div>
        );
        day = addDays(day, 1);
      }
      rows.push(
        <div key={day.toString()} className="grid grid-cols-7">
          {days}
        </div>
      );
      days = [];
    }

    return (
      <div>
        {/* Days of week header */}
        <div className="grid grid-cols-7 bg-gray-50 border border-gray-200">
          {['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'].map((day) => (
            <div key={day} className="p-3 text-center text-sm font-medium text-gray-700 border-r border-gray-200 last:border-r-0">
              {day}
            </div>
          ))}
        </div>
        {rows}
      </div>
    );
  };

  // Render Week View
  const renderWeekView = () => {
    const weekStart = startOfWeek(currentDate, { locale: ptBR });
    const weekDays = [];
    
    for (let i = 0; i < 7; i++) {
      const day = addDays(weekStart, i);
      const dayAppointments = getAppointmentsForDate(day);
      
      weekDays.push(
        <div key={day.toString()} className="border border-gray-200 bg-white">
          <div className={`p-3 text-center border-b border-gray-200 ${
            isSameDay(day, new Date()) ? 'bg-blue-50 text-blue-600 font-semibold' : 'bg-gray-50'
          }`}>
            <div className="text-sm font-medium">
              {format(day, 'EEE', { locale: ptBR })}
            </div>
            <div className="text-lg">
              {format(day, 'd')}
            </div>
          </div>
          
          <div className="p-2 min-h-[400px] space-y-2">
            {dayAppointments.map((appointment) => (
              <div
                key={appointment.id}
                className={`p-2 rounded border-l-4 cursor-pointer hover:opacity-80 ${getStatusColor(appointment.status)}`}
                onClick={() => openDetailModal(appointment)}
              >
                <div className="font-medium text-sm">
                  {formatTime(appointment.appointment_time)}
                </div>
                <div className="text-xs opacity-90 truncate">
                  {appointment.patient_name}
                </div>
                <div className="text-xs opacity-75 truncate">
                  {appointment.service_name}
                </div>
              </div>
            ))}
            
            <button
              onClick={() => openCreateModal(day)}
              className="w-full p-2 border-2 border-dashed border-gray-300 rounded text-gray-500 hover:border-red-300 hover:text-red-600 transition-colors text-sm"
            >
              + Novo agendamento
            </button>
          </div>
        </div>
      );
    }

    return (
      <div className="grid grid-cols-7 gap-0 border border-gray-200 rounded-lg overflow-hidden">
        {weekDays}
      </div>
    );
  };

  // Render Day View
  const renderDayView = () => {
    const dayAppointments = getAppointmentsForDate(currentDate);
    const hours = Array.from({ length: 24 }, (_, i) => i);

    return (
      <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
        <div className={`p-4 text-center border-b border-gray-200 ${
          isSameDay(currentDate, new Date()) ? 'bg-blue-50 text-blue-600' : 'bg-gray-50'
        }`}>
          <h3 className="text-lg font-semibold">
            {format(currentDate, "EEEE, d 'de' MMMM 'de' yyyy", { locale: ptBR })}
          </h3>
          <p className="text-sm text-gray-600">
            {dayAppointments.length} agendamento(s)
          </p>
        </div>
        
        <div className="max-h-[600px] overflow-y-auto">
          {hours.map((hour) => {
            const hourAppointments = dayAppointments.filter(apt => {
              const aptHour = parseInt(apt.appointment_time.split(':')[0]);
              return aptHour === hour;
            });

            return (
              <div key={hour} className="border-b border-gray-100 last:border-b-0">
                <div className="flex">
                  <div className="w-16 p-3 text-sm text-gray-500 bg-gray-50 border-r border-gray-200 text-center">
                    {hour.toString().padStart(2, '0')}:00
                  </div>
                  <div className="flex-1 p-2 min-h-[60px]">
                    {hourAppointments.length > 0 ? (
                      <div className="space-y-1">
                        {hourAppointments.map((appointment) => (
                          <div
                            key={appointment.id}
                            className={`p-2 rounded border-l-4 cursor-pointer hover:opacity-80 ${getStatusColor(appointment.status)}`}
                            onClick={() => openDetailModal(appointment)}
                          >
                            <div className="flex justify-between items-start">
                              <div>
                                <div className="font-medium text-sm">
                                  {formatTime(appointment.appointment_time)} - {appointment.patient_name}
                                </div>
                                <div className="text-xs opacity-90">
                                  {appointment.service_name}
                                </div>
                                <div className="text-xs opacity-75">
                                  {formatCurrency(appointment.value)}
                                </div>
                              </div>
                              <div className="text-xs opacity-75">
                                {getStatusText(appointment.status)}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <button
                        onClick={() => {
                          const appointmentDate = new Date(currentDate);
                          appointmentDate.setHours(hour, 0, 0, 0);
                          openCreateModal(appointmentDate);
                        }}
                        className="w-full h-full text-gray-400 hover:text-red-600 hover:bg-red-50 transition-colors text-sm"
                      >
                        + Novo agendamento
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda de Atendimentos</h1>
          <p className="text-gray-600">Visualize e gerencie seus agendamentos</p>
        </div>
        
        <button
          onClick={() => openCreateModal()}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Novo Agendamento
        </button>
      </div>

      {/* Calendar Controls */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          {/* View Mode Selector */}
          <div className="flex bg-gray-100 rounded-lg p-1">
            {(['month', 'week', 'day'] as ViewMode[]).map((mode) => (
              <button
                key={mode}
                onClick={() => setViewMode(mode)}
                className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  viewMode === mode
                    ? 'bg-white text-red-600 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                {mode === 'month' ? 'Mês' : mode === 'week' ? 'Semana' : 'Dia'}
              </button>
            ))}
          </div>

          {/* Navigation */}
          <div className="flex items-center space-x-4">
            <button
              onClick={() => navigateCalendar('prev')}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ChevronLeft className="h-5 w-5 text-gray-600" />
            </button>
            
            <h2 className="text-lg font-semibold text-gray-900 min-w-[200px] text-center">
              {getViewTitle()}
            </h2>
            
            <button
              onClick={() => navigateCalendar('next')}
              className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <ChevronRight className="h-5 w-5 text-gray-600" />
            </button>
          </div>

          {/* Today Button */}
          <button
            onClick={() => setCurrentDate(new Date())}
            className="btn btn-outline"
          >
            Hoje
          </button>
        </div>

        {/* Status Legend */}
        <div className="flex flex-wrap gap-4 mt-4 pt-4 border-t border-gray-200">
          <div className="flex items-center">
            <div className="w-3 h-3 bg-blue-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Agendado</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 bg-green-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Realizado</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 bg-red-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Cancelado</span>
          </div>
          <div className="flex items-center">
            <div className="w-3 h-3 bg-yellow-500 rounded mr-2"></div>
            <span className="text-sm text-gray-600">Faltou</span>
          </div>
        </div>

        {/* Debug info */}
        <div className="mt-4 pt-4 border-t border-gray-200 text-xs text-gray-500">
          <p>📊 Total de agendamentos carregados: {appointments.length}</p>
          <p>📅 Período atual: {getDateRange().start} até {getDateRange().end}</p>
        </div>
      </div>

      {/* Error and Success Messages */}
      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 flex items-center">
          <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6">
          {success}
        </div>
      )}

      {/* Calendar View */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando agenda...</p>
          </div>
        ) : (
          <>
            {viewMode === 'month' && renderMonthView()}
            {viewMode === 'week' && renderWeekView()}
            {viewMode === 'day' && renderDayView()}
          </>
        )}
      </div>

      {/* Appointment Detail Modal */}
      {isDetailModalOpen && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-xl font-bold">Detalhes do Agendamento</h2>
              <button
                onClick={closeModal}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              <div className="flex items-center justify-between">
                <span className="font-medium text-gray-700">Status:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(selectedAppointment.status)}`}>
                  {getStatusText(selectedAppointment.status)}
                </span>
              </div>

              <div className="space-y-3">
                <div className="flex items-center">
                  <User className="h-4 w-4 text-gray-400 mr-3" />
                  <div>
                    <div className="font-medium">{selectedAppointment.patient_name}</div>
                    <div className="text-sm text-gray-500">
                      CPF: {selectedAppointment.patient_cpf?.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')}
                    </div>
                  </div>
                </div>

                <div className="flex items-center">
                  <Calendar className="h-4 w-4 text-gray-400 mr-3" />
                  <div>
                    <div className="font-medium">
                      {format(new Date(selectedAppointment.appointment_date), "dd 'de' MMMM 'de' yyyy", { locale: ptBR })}
                    </div>
                    <div className="text-sm text-gray-500">
                      {formatTime(selectedAppointment.appointment_time)}
                    </div>
                  </div>
                </div>

                <div className="flex items-center">
                  <Clock className="h-4 w-4 text-gray-400 mr-3" />
                  <div>
                    <div className="font-medium">{selectedAppointment.service_name}</div>
                    <div className="text-sm text-gray-500">
                      {formatCurrency(selectedAppointment.value)}
                    </div>
                  </div>
                </div>

                {selectedAppointment.location_name && (
                  <div className="flex items-start">
                    <MapPin className="h-4 w-4 text-gray-400 mr-3 mt-0.5" />
                    <div>
                      <div className="font-medium">{selectedAppointment.location_name}</div>
                      {selectedAppointment.location_address && (
                        <div className="text-sm text-gray-500">
                          {selectedAppointment.location_address}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {selectedAppointment.notes && (
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <div className="font-medium text-gray-700 mb-1">Observações:</div>
                    <div className="text-sm text-gray-600">{selectedAppointment.notes}</div>
                  </div>
                )}
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 flex justify-end space-x-3">
              <button
                onClick={() => openEditModal(selectedAppointment)}
                className="btn btn-secondary flex items-center"
              >
                <Edit className="h-4 w-4 mr-2" />
                Editar
              </button>
              <button
                onClick={() => confirmDelete(selectedAppointment)}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Excluir
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Appointment form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {modalMode === 'create' ? 'Novo Agendamento' : 'Editar Agendamento'}
              </h2>
              <p className="text-gray-600 text-sm mt-1">
                Agendamentos são apenas para pacientes particulares
              </p>
            </div>

            {error && (
              <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg">
                {error}
              </div>
            )}

            {success && (
              <div className="mx-6 mt-4 bg-green-50 text-green-600 p-3 rounded-lg">
                {success}
              </div>
            )}

            <form onSubmit={handleSubmit} className="p-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Paciente Particular *
                  </label>
                  <select
                    name="private_patient_id"
                    value={formData.private_patient_id}
                    onChange={handleInputChange}
                    className="input"
                    required
                  >
                    <option value="">Selecione um paciente</option>
                    {privatePatients.map((patient) => (
                      <option key={patient.id} value={patient.id}>
                        {patient.name} - CPF: {patient.cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Serviço *
                  </label>
                  <select
                    name="service_id"
                    value={formData.service_id}
                    onChange={handleServiceChange}
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

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Data *
                    </label>
                    <input
                      type="date"
                      name="appointment_date"
                      value={formData.appointment_date}
                      onChange={handleInputChange}
                      className="input"
                      min={new Date().toISOString().split('T')[0]}
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Hora *
                    </label>
                    <input
                      type="time"
                      name="appointment_time"
                      value={formData.appointment_time}
                      onChange={handleInputChange}
                      className="input"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Local de Atendimento
                  </label>
                  <select
                    name="location_id"
                    value={formData.location_id}
                    onChange={handleInputChange}
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

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Valor (R$) *
                  </label>
                  <input
                    type="number"
                    name="value"
                    value={formData.value}
                    onChange={handleInputChange}
                    className="input"
                    min="0"
                    step="0.01"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Observações
                  </label>
                  <textarea
                    name="notes"
                    value={formData.notes}
                    onChange={handleInputChange}
                    className="input min-h-[80px]"
                    rows={3}
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {modalMode === 'create' ? 'Criar Agendamento' : 'Salvar Alterações'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && appointmentToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir este agendamento?
              Esta ação não pode ser desfeita.
            </p>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelDelete}
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