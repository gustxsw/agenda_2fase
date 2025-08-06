import React, { useState, useEffect } from 'react';
import { Calendar, Plus, Clock, User, Users, MapPin, DollarSign, Search, X, Check, AlertTriangle, Eye, ChevronLeft, ChevronRight } from 'lucide-react';

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
  status: 'scheduled' | 'confirmed' | 'completed' | 'cancelled';
  notes: string;
  private_patient_id: number | null;
  client_id: number | null;
  dependent_id: number | null;
};

type Service = {
  id: number;
  name: string;
  base_price: number;
  category_name: string;
};

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  is_default: boolean;
};

type Client = {
  id: number;
  name: string;
  cpf: string;
  subscription_status: string;
};

type Dependent = {
  id: number;
  name: string;
  cpf: string;
  client_id: number;
  client_name: string;
  client_subscription_status: string;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
};

type ViewMode = 'month' | 'week' | 'day';

const SchedulingPage: React.FC = () => {
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [locations, setLocations] = useState<AttendanceLocation[]>([]);
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Calendar state
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState<string>('');
  const [viewMode, setViewMode] = useState<ViewMode>('month');
  
  // Modal state
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  
  // Form state
  const [formData, setFormData] = useState({
    patient_type: 'particular' as 'particular' | 'convenio',
    private_patient_id: '',
    client_id: '',
    dependent_id: '',
    service_id: '',
    appointment_date: '',
    appointment_time: '',
    location_id: '',
    value: '',
    notes: '',
    cpf_search: ''
  });
  
  // Search state
  const [isSearching, setIsSearching] = useState(false);
  const [foundClient, setFoundClient] = useState<Client | null>(null);
  const [foundDependent, setFoundDependent] = useState<Dependent | null>(null);
  const [dependents, setDependents] = useState<Dependent[]>([]);

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
    fetchData();
  }, [currentDate, viewMode]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Get date range based on view mode
      let startDate, endDate;
      
      if (viewMode === 'month') {
        startDate = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
        endDate = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
      } else if (viewMode === 'week') {
        const dayOfWeek = currentDate.getDay();
        startDate = new Date(currentDate);
        startDate.setDate(currentDate.getDate() - dayOfWeek);
        endDate = new Date(startDate);
        endDate.setDate(startDate.getDate() + 6);
      } else { // day
        startDate = new Date(currentDate);
        endDate = new Date(currentDate);
      }

      console.log('🔄 Fetching appointments from:', startDate.toISOString().split('T')[0], 'to', endDate.toISOString().split('T')[0]);

      // Fetch appointments
      const appointmentsResponse = await fetch(
        `${apiUrl}/api/scheduling/appointments?start_date=${startDate.toISOString().split('T')[0]}&end_date=${endDate.toISOString().split('T')[0]}`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      if (appointmentsResponse.ok) {
        const appointmentsData = await appointmentsResponse.json();
        console.log('✅ Appointments loaded:', appointmentsData);
        setAppointments(appointmentsData);
      } else {
        console.error('❌ Failed to load appointments');
      }

      // Fetch services
      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (servicesResponse.ok) {
        const servicesData = await servicesResponse.json();
        console.log('✅ Services loaded:', servicesData);
        setServices(servicesData);
      }

      // Fetch locations
      const locationsResponse = await fetch(`${apiUrl}/api/attendance-locations`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        console.log('✅ Locations loaded:', locationsData);
        setLocations(locationsData);
      }

      // Fetch private patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        console.log('✅ Private patients loaded:', patientsData);
        setPrivatePatients(patientsData);
      }

    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  const openCreateModal = (date?: string) => {
    const defaultLocation = locations.find(l => l.is_default);
    
    setFormData({
      patient_type: 'particular',
      private_patient_id: '',
      client_id: '',
      dependent_id: '',
      service_id: '',
      appointment_date: date || '',
      appointment_time: '',
      location_id: defaultLocation?.id.toString() || '',
      value: '',
      notes: '',
      cpf_search: ''
    });
    setFoundClient(null);
    setFoundDependent(null);
    setDependents([]);
    setSelectedDate(date || '');
    setIsCreateModalOpen(true);
    setError('');
    setSuccess('');
  };

  const openViewModal = (appointment: Appointment) => {
    setSelectedAppointment(appointment);
    setIsViewModalOpen(true);
  };

  const closeModals = () => {
    setIsCreateModalOpen(false);
    setIsViewModalOpen(false);
    setSelectedAppointment(null);
    setError('');
    setSuccess('');
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const serviceId = e.target.value;
    setFormData(prev => ({ ...prev, service_id: serviceId }));
    
    if (serviceId) {
      const service = services.find(s => s.id === parseInt(serviceId));
      if (service) {
        setFormData(prev => ({ ...prev, value: service.base_price.toString() }));
      }
    }
  };

  const searchByCpf = async () => {
    if (!formData.cpf_search) return;
    
    setError('');
    setIsSearching(true);
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      const cleanCpf = formData.cpf_search.replace(/\D/g, '');

      console.log('🔍 Searching for CPF:', cleanCpf);

      // Search for dependent first
      const dependentResponse = await fetch(`${apiUrl}/api/dependents/lookup?cpf=${cleanCpf}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (dependentResponse.ok) {
        const dependentData = await dependentResponse.json();
        console.log('✅ Dependent found:', dependentData);
        
        if (dependentData.client_subscription_status !== 'active') {
          setError('Este dependente não pode ser atendido pois o titular não possui assinatura ativa.');
          return;
        }
        
        setFoundDependent(dependentData);
        setFoundClient(null);
        setFormData(prev => ({
          ...prev,
          client_id: '',
          dependent_id: dependentData.id.toString()
        }));
        return;
      }

      // Search for client
      const clientResponse = await fetch(`${apiUrl}/api/clients/lookup?cpf=${cleanCpf}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (clientResponse.ok) {
        const clientData = await clientResponse.json();
        console.log('✅ Client found:', clientData);
        
        if (clientData.subscription_status !== 'active') {
          setError('Este cliente não pode ser atendido pois não possui assinatura ativa.');
          return;
        }
        
        setFoundClient(clientData);
        setFoundDependent(null);
        setFormData(prev => ({
          ...prev,
          client_id: clientData.id.toString(),
          dependent_id: ''
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
        setError('Cliente ou dependente não encontrado');
        setFoundClient(null);
        setFoundDependent(null);
        setDependents([]);
      }
    } catch (error) {
      console.error('Error searching:', error);
      setError('Erro ao buscar cliente');
    } finally {
      setIsSearching(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validation
    if (formData.patient_type === 'particular' && !formData.private_patient_id) {
      setError('Selecione um paciente particular');
      return;
    }

    if (formData.patient_type === 'convenio' && !formData.client_id && !formData.dependent_id) {
      setError('Busque e selecione um cliente ou dependente');
      return;
    }

    if (!formData.service_id) {
      setError('Selecione um serviço');
      return;
    }

    if (!formData.appointment_date || !formData.appointment_time) {
      setError('Data e hora são obrigatórios');
      return;
    }

    if (!formData.value || parseFloat(formData.value) <= 0) {
      setError('Valor deve ser maior que zero');
      return;
    }

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const appointmentData = {
        private_patient_id: formData.patient_type === 'particular' ? parseInt(formData.private_patient_id) : null,
        client_id: formData.patient_type === 'convenio' && !formData.dependent_id ? parseInt(formData.client_id) : null,
        dependent_id: formData.patient_type === 'convenio' && formData.dependent_id ? parseInt(formData.dependent_id) : null,
        service_id: parseInt(formData.service_id),
        appointment_date: formData.appointment_date,
        appointment_time: formData.appointment_time,
        location_id: formData.location_id ? parseInt(formData.location_id) : null,
        value: parseFloat(formData.value),
        notes: formData.notes
      };

      console.log('🔄 Creating appointment:', appointmentData);

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

      const result = await response.json();
      console.log('✅ Appointment created:', result);

      setSuccess('Agendamento criado com sucesso!');
      await fetchData();
      
      setTimeout(() => {
        closeModals();
      }, 1500);
    } catch (error) {
      console.error('Error creating appointment:', error);
      setError(error instanceof Error ? error.message : 'Erro ao criar agendamento');
    }
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    return limitedValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };

  const formatTime = (timeString: string) => {
    return timeString.slice(0, 5);
  };

  const getStatusInfo = (status: string) => {
    switch (status) {
      case 'scheduled':
        return {
          color: 'bg-blue-500',
          textColor: 'text-blue-700',
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200',
          label: 'Agendado',
          emoji: '📅'
        };
      case 'confirmed':
        return {
          color: 'bg-green-500',
          textColor: 'text-green-700',
          bgColor: 'bg-green-50',
          borderColor: 'border-green-200',
          label: 'Confirmado',
          emoji: '✅'
        };
      case 'completed':
        return {
          color: 'bg-purple-500',
          textColor: 'text-purple-700',
          bgColor: 'bg-purple-50',
          borderColor: 'border-purple-200',
          label: 'Realizado',
          emoji: '✔️'
        };
      case 'cancelled':
        return {
          color: 'bg-red-500',
          textColor: 'text-red-700',
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
          label: 'Cancelado',
          emoji: '❌'
        };
      default:
        return {
          color: 'bg-gray-500',
          textColor: 'text-gray-700',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
          label: 'Desconhecido',
          emoji: '❓'
        };
    }
  };

  const getPatientTypeInfo = (appointment: Appointment) => {
    if (appointment.private_patient_id) {
      return { icon: '👤', label: 'Particular', color: 'text-purple-600' };
    } else if (appointment.dependent_id) {
      return { icon: '👥', label: 'Dependente', color: 'text-blue-600' };
    } else {
      return { icon: '🏥', label: 'Convênio', color: 'text-green-600' };
    }
  };

  // Navigation functions
  const navigateDate = (direction: 'prev' | 'next') => {
    setCurrentDate(prev => {
      const newDate = new Date(prev);
      if (viewMode === 'month') {
        newDate.setMonth(newDate.getMonth() + (direction === 'next' ? 1 : -1));
      } else if (viewMode === 'week') {
        newDate.setDate(newDate.getDate() + (direction === 'next' ? 7 : -7));
      } else { // day
        newDate.setDate(newDate.getDate() + (direction === 'next' ? 1 : -1));
      }
      return newDate;
    });
  };

  const goToToday = () => {
    setCurrentDate(new Date());
  };

  // Generate calendar days for month view
  const generateMonthDays = () => {
    const year = currentDate.getFullYear();
    const month = currentDate.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const startDate = new Date(firstDay);
    startDate.setDate(startDate.getDate() - firstDay.getDay());
    
    const days = [];
    const currentDateObj = new Date(startDate);
    
    for (let i = 0; i < 42; i++) {
      const dateStr = currentDateObj.toISOString().split('T')[0];
      const dayAppointments = appointments.filter(apt => apt.appointment_date === dateStr);
      
      days.push({
        date: new Date(currentDateObj),
        dateStr,
        isCurrentMonth: currentDateObj.getMonth() === month,
        isToday: dateStr === new Date().toISOString().split('T')[0],
        appointments: dayAppointments
      });
      
      currentDateObj.setDate(currentDateObj.getDate() + 1);
    }
    
    return days;
  };

  // Generate week days for week view
  const generateWeekDays = () => {
    const days = [];
    const startOfWeek = new Date(currentDate);
    startOfWeek.setDate(currentDate.getDate() - currentDate.getDay());
    
    for (let i = 0; i < 7; i++) {
      const day = new Date(startOfWeek);
      day.setDate(startOfWeek.getDate() + i);
      const dateStr = day.toISOString().split('T')[0];
      const dayAppointments = appointments.filter(apt => apt.appointment_date === dateStr);
      
      days.push({
        date: day,
        dateStr,
        isToday: dateStr === new Date().toISOString().split('T')[0],
        appointments: dayAppointments
      });
    }
    
    return days;
  };

  // Generate day view
  const generateDayView = () => {
    const dateStr = currentDate.toISOString().split('T')[0];
    const dayAppointments = appointments.filter(apt => apt.appointment_date === dateStr);
    
    // Sort appointments by time
    dayAppointments.sort((a, b) => a.appointment_time.localeCompare(b.appointment_time));
    
    return dayAppointments;
  };

  const getViewTitle = () => {
    const monthNames = [
      'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
      'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'
    ];

    if (viewMode === 'month') {
      return `${monthNames[currentDate.getMonth()]} ${currentDate.getFullYear()}`;
    } else if (viewMode === 'week') {
      const startOfWeek = new Date(currentDate);
      startOfWeek.setDate(currentDate.getDate() - currentDate.getDay());
      const endOfWeek = new Date(startOfWeek);
      endOfWeek.setDate(startOfWeek.getDate() + 6);
      
      return `${startOfWeek.getDate()} - ${endOfWeek.getDate()} de ${monthNames[currentDate.getMonth()]} ${currentDate.getFullYear()}`;
    } else {
      return `${currentDate.getDate()} de ${monthNames[currentDate.getMonth()]} ${currentDate.getFullYear()}`;
    }
  };

  const weekDays = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
  const weekDaysFull = ['Domingo', 'Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado'];

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda</h1>
          <p className="text-gray-600">Gerencie seus agendamentos</p>
        </div>
        
        <button
          onClick={() => openCreateModal()}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Novo Agendamento
        </button>
      </div>

      {/* View Mode Selector */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-700">Visualização:</span>
            <div className="flex bg-gray-100 rounded-lg p-1">
              <button
                onClick={() => setViewMode('month')}
                className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                  viewMode === 'month' 
                    ? 'bg-red-600 text-white' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Mês
              </button>
              <button
                onClick={() => setViewMode('week')}
                className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                  viewMode === 'week' 
                    ? 'bg-red-600 text-white' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Semana
              </button>
              <button
                onClick={() => setViewMode('day')}
                className={`px-3 py-1 rounded-md text-sm font-medium transition-colors ${
                  viewMode === 'day' 
                    ? 'bg-red-600 text-white' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Dia
              </button>
            </div>
          </div>

          <button
            onClick={goToToday}
            className="btn btn-secondary text-sm"
          >
            Hoje
          </button>
        </div>
      </div>

      {/* Status Legend */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4 mb-6">
        <h3 className="text-sm font-medium text-gray-700 mb-3">Legenda de Status</h3>
        <div className="flex flex-wrap gap-4">
          {[
            { status: 'scheduled', info: getStatusInfo('scheduled') },
            { status: 'confirmed', info: getStatusInfo('confirmed') },
            { status: 'completed', info: getStatusInfo('completed') },
            { status: 'cancelled', info: getStatusInfo('cancelled') }
          ].map(({ status, info }) => (
            <div key={status} className="flex items-center">
              <div className={`w-3 h-3 rounded-full ${info.color} mr-2`}></div>
              <span className="text-sm text-gray-600">
                {info.emoji} {info.label}
              </span>
            </div>
          ))}
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

      {/* Calendar */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        {/* Calendar Header */}
        <div className="flex justify-between items-center mb-6">
          <button
            onClick={() => navigateDate('prev')}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
          
          <h2 className="text-xl font-semibold">
            {getViewTitle()}
          </h2>
          
          <button
            onClick={() => navigateDate('next')}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        </div>

        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando agenda...</p>
          </div>
        ) : (
          <>
            {/* Month View */}
            {viewMode === 'month' && (
              <>
                {/* Week Days Header */}
                <div className="grid grid-cols-7 gap-1 mb-2">
                  {weekDays.map(day => (
                    <div key={day} className="p-2 text-center text-sm font-medium text-gray-500">
                      {day}
                    </div>
                  ))}
                </div>

                {/* Calendar Grid */}
                <div className="grid grid-cols-7 gap-1">
                  {generateMonthDays().map((day, index) => (
                    <div
                      key={index}
                      className={`min-h-[120px] p-2 border border-gray-100 relative ${
                        day.isCurrentMonth ? 'bg-white' : 'bg-gray-50'
                      } ${day.isToday ? 'ring-2 ring-red-200' : ''}`}
                    >
                      {/* Date number */}
                      <div className="flex justify-between items-start mb-2">
                        <span className={`text-sm font-medium ${
                          day.isCurrentMonth ? 'text-gray-900' : 'text-gray-400'
                        } ${day.isToday ? 'text-red-600' : ''}`}>
                          {day.date.getDate()}
                        </span>
                        
                        {/* Add appointment button */}
                        {day.isCurrentMonth && (
                          <button
                            onClick={() => openCreateModal(day.dateStr)}
                            className="w-6 h-6 bg-red-100 hover:bg-red-200 text-red-600 rounded-full flex items-center justify-center text-xs transition-colors"
                            title="Novo agendamento"
                          >
                            +
                          </button>
                        )}
                      </div>

                      {/* Appointments */}
                      <div className="space-y-1">
                        {day.appointments.slice(0, 3).map((appointment) => {
                          const statusInfo = getStatusInfo(appointment.status);
                          const patientInfo = getPatientTypeInfo(appointment);
                          
                          return (
                            <button
                              key={appointment.id}
                              onClick={() => openViewModal(appointment)}
                              className={`w-full text-left p-1 rounded text-xs ${statusInfo.bgColor} ${statusInfo.borderColor} border hover:opacity-80 transition-opacity`}
                            >
                              <div className="flex items-center justify-between">
                                <span className={`font-medium ${statusInfo.textColor}`}>
                                  {formatTime(appointment.appointment_time)}
                                </span>
                                <span className="text-xs">
                                  {statusInfo.emoji}
                                </span>
                              </div>
                              <div className="flex items-center mt-1">
                                <span className="text-xs mr-1">{patientInfo.icon}</span>
                                <span className={`text-xs truncate ${statusInfo.textColor}`}>
                                  {appointment.patient_name}
                                </span>
                              </div>
                            </button>
                          );
                        })}
                        
                        {day.appointments.length > 3 && (
                          <div className="text-xs text-gray-500 text-center">
                            +{day.appointments.length - 3} mais
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* Week View */}
            {viewMode === 'week' && (
              <>
                <div className="grid grid-cols-7 gap-4">
                  {generateWeekDays().map((day, index) => (
                    <div key={index} className="min-h-[400px]">
                      {/* Day header */}
                      <div className={`text-center p-3 rounded-t-lg ${
                        day.isToday ? 'bg-red-100 text-red-700' : 'bg-gray-50 text-gray-700'
                      }`}>
                        <div className="text-sm font-medium">{weekDays[index]}</div>
                        <div className={`text-lg font-bold ${day.isToday ? 'text-red-600' : ''}`}>
                          {day.date.getDate()}
                        </div>
                      </div>

                      {/* Day content */}
                      <div className="border border-t-0 border-gray-200 rounded-b-lg p-2 min-h-[350px] bg-white">
                        <button
                          onClick={() => openCreateModal(day.dateStr)}
                          className="w-full mb-2 p-2 border-2 border-dashed border-gray-300 rounded-lg text-gray-500 hover:border-red-300 hover:text-red-600 transition-colors"
                        >
                          <Plus className="h-4 w-4 mx-auto" />
                        </button>

                        <div className="space-y-2">
                          {day.appointments.map((appointment) => {
                            const statusInfo = getStatusInfo(appointment.status);
                            const patientInfo = getPatientTypeInfo(appointment);
                            
                            return (
                              <button
                                key={appointment.id}
                                onClick={() => openViewModal(appointment)}
                                className={`w-full text-left p-2 rounded-lg ${statusInfo.bgColor} ${statusInfo.borderColor} border hover:opacity-80 transition-opacity`}
                              >
                                <div className="flex items-center justify-between mb-1">
                                  <span className={`text-sm font-medium ${statusInfo.textColor}`}>
                                    {formatTime(appointment.appointment_time)}
                                  </span>
                                  <span className="text-xs">
                                    {statusInfo.emoji}
                                  </span>
                                </div>
                                <div className="flex items-center">
                                  <span className="text-xs mr-1">{patientInfo.icon}</span>
                                  <span className={`text-xs ${statusInfo.textColor}`}>
                                    {appointment.patient_name}
                                  </span>
                                </div>
                                <div className={`text-xs ${statusInfo.textColor} mt-1`}>
                                  {appointment.service_name}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}

            {/* Day View */}
            {viewMode === 'day' && (
              <div className="max-w-2xl mx-auto">
                <div className="text-center mb-6">
                  <h3 className="text-lg font-semibold text-gray-900">
                    {weekDaysFull[currentDate.getDay()]}, {currentDate.getDate()}
                  </h3>
                  <button
                    onClick={() => openCreateModal(currentDate.toISOString().split('T')[0])}
                    className="btn btn-outline mt-2 flex items-center mx-auto"
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Novo Agendamento
                  </button>
                </div>

                <div className="space-y-3">
                  {generateDayView().length === 0 ? (
                    <div className="text-center py-12 bg-gray-50 rounded-lg">
                      <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                      <h3 className="text-lg font-medium text-gray-900 mb-2">
                        Nenhum agendamento para hoje
                      </h3>
                      <p className="text-gray-600 mb-4">
                        Você não possui agendamentos para este dia.
                      </p>
                      <button
                        onClick={() => openCreateModal(currentDate.toISOString().split('T')[0])}
                        className="btn btn-primary inline-flex items-center"
                      >
                        <Plus className="h-5 w-5 mr-2" />
                        Criar Agendamento
                      </button>
                    </div>
                  ) : (
                    generateDayView().map((appointment) => {
                      const statusInfo = getStatusInfo(appointment.status);
                      const patientInfo = getPatientTypeInfo(appointment);
                      
                      return (
                        <button
                          key={appointment.id}
                          onClick={() => openViewModal(appointment)}
                          className={`w-full text-left p-4 rounded-lg ${statusInfo.bgColor} ${statusInfo.borderColor} border-2 hover:opacity-80 transition-opacity`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center">
                              <Clock className="h-5 w-5 mr-2 text-gray-500" />
                              <span className={`text-lg font-medium ${statusInfo.textColor}`}>
                                {formatTime(appointment.appointment_time)}
                              </span>
                            </div>
                            <span className={`px-3 py-1 rounded-full text-sm font-medium flex items-center ${statusInfo.bgColor} ${statusInfo.textColor}`}>
                              <span className="mr-1">{statusInfo.emoji}</span>
                              {statusInfo.label}
                            </span>
                          </div>
                          
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <div className="flex items-center mb-1">
                                <span className="mr-2">{patientInfo.icon}</span>
                                <span className={`font-medium ${statusInfo.textColor}`}>
                                  {appointment.patient_name}
                                </span>
                              </div>
                              <span className={`text-sm ${patientInfo.color}`}>
                                {patientInfo.label}
                              </span>
                            </div>
                            
                            <div className="text-right">
                              <div className={`font-medium ${statusInfo.textColor}`}>
                                {appointment.service_name}
                              </div>
                              <div className={`text-sm ${statusInfo.textColor}`}>
                                {formatCurrency(appointment.value)}
                              </div>
                            </div>
                          </div>
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Create Appointment Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">Novo Agendamento</h2>
              {selectedDate && (
                <p className="text-sm text-gray-600 mt-1">
                  Data selecionada: {new Date(selectedDate).toLocaleDateString('pt-BR')}
                </p>
              )}
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
              <div className="space-y-6">
                {/* Patient Type Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-3">
                    Tipo de Paciente
                  </label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      type="button"
                      onClick={() => {
                        setFormData(prev => ({ ...prev, patient_type: 'particular' }));
                        setFoundClient(null);
                        setFoundDependent(null);
                        setDependents([]);
                      }}
                      className={`p-3 rounded-lg border-2 transition-all ${
                        formData.patient_type === 'particular'
                          ? 'border-red-600 bg-red-50 text-red-700'
                          : 'border-gray-200 bg-white text-gray-700 hover:border-gray-300'
                      }`}
                    >
                      <User className="h-6 w-6 mx-auto mb-2" />
                      <div className="text-sm font-medium">Particular</div>
                    </button>
                    
                    <button
                      type="button"
                      onClick={() => {
                        setFormData(prev => ({ ...prev, patient_type: 'convenio' }));
                        setFormData(prev => ({ ...prev, private_patient_id: '' }));
                      }}
                      className={`p-3 rounded-lg border-2 transition-all ${
                        formData.patient_type === 'convenio'
                          ? 'border-red-600 bg-red-50 text-red-700'
                          : 'border-gray-200 bg-white text-gray-700 hover:border-gray-300'
                      }`}
                    >
                      <Users className="h-6 w-6 mx-auto mb-2" />
                      <div className="text-sm font-medium">Convênio</div>
                    </button>
                  </div>
                </div>

                {/* Patient Selection */}
                {formData.patient_type === 'particular' ? (
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
                          {patient.name} - {formatCpf(patient.cpf)}
                        </option>
                      ))}
                    </select>
                    {privatePatients.length === 0 && (
                      <p className="text-sm text-gray-500 mt-1">
                        Nenhum paciente particular cadastrado. Vá em "Pacientes Particulares" para adicionar.
                      </p>
                    )}
                  </div>
                ) : (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Buscar Cliente por CPF *
                    </label>
                    <div className="flex space-x-2">
                      <input
                        type="text"
                        value={formData.cpf_search}
                        onChange={(e) => setFormData(prev => ({ ...prev, cpf_search: formatCpf(e.target.value) }))}
                        className="input flex-1"
                        placeholder="000.000.000-00"
                      />
                      <button
                        type="button"
                        onClick={searchByCpf}
                        className={`btn btn-primary ${isSearching ? 'opacity-70' : ''}`}
                        disabled={isSearching}
                      >
                        {isSearching ? 'Buscando...' : 'Buscar'}
                      </button>
                    </div>

                    {/* Found client/dependent display */}
                    {foundClient && (
                      <div className="mt-3 p-3 bg-green-50 rounded-lg">
                        <p className="text-green-700">
                          <strong>Cliente encontrado:</strong> {foundClient.name}
                        </p>
                        <p className="text-green-600 text-sm">
                          Status: {foundClient.subscription_status === 'active' ? 'Ativo' : 'Inativo'}
                        </p>
                        
                        {dependents.length > 0 && (
                          <div className="mt-2">
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              Dependente (opcional)
                            </label>
                            <select
                              name="dependent_id"
                              value={formData.dependent_id}
                              onChange={handleInputChange}
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

                    {foundDependent && (
                      <div className="mt-3 p-3 bg-blue-50 rounded-lg">
                        <p className="text-blue-700">
                          <strong>Dependente encontrado:</strong> {foundDependent.name}
                        </p>
                        <p className="text-blue-600 text-sm">
                          Titular: {foundDependent.client_name}
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* Service Selection */}
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
                  {services.length === 0 && (
                    <p className="text-sm text-gray-500 mt-1">
                      Nenhum serviço cadastrado. Entre em contato com o administrador.
                    </p>
                  )}
                </div>

                {/* Date and Time */}
                <div className="grid grid-cols-2 gap-4">
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

                {/* Location and Value */}
                <div className="grid grid-cols-2 gap-4">
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
                </div>

                {/* Notes */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Observações
                  </label>
                  <textarea
                    name="notes"
                    value={formData.notes}
                    onChange={handleInputChange}
                    className="input min-h-[80px]"
                    placeholder="Observações sobre o agendamento..."
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeModals}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button 
                  type="submit" 
                  className="btn btn-primary"
                  disabled={
                    (formData.patient_type === 'particular' && !formData.private_patient_id) ||
                    (formData.patient_type === 'convenio' && !foundClient && !foundDependent) ||
                    !formData.service_id ||
                    !formData.appointment_date ||
                    !formData.appointment_time ||
                    !formData.value
                  }
                >
                  Criar Agendamento
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View Appointment Modal */}
      {isViewModalOpen && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-xl font-bold">Detalhes do Agendamento</h2>
              <button
                onClick={closeModals}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="p-6 space-y-4">
              {/* Status */}
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-gray-700">Status:</span>
                <span className={`px-3 py-1 rounded-full text-sm font-medium flex items-center ${
                  getStatusInfo(selectedAppointment.status).bgColor
                } ${getStatusInfo(selectedAppointment.status).textColor}`}>
                  <span className="mr-1">{getStatusInfo(selectedAppointment.status).emoji}</span>
                  {getStatusInfo(selectedAppointment.status).label}
                </span>
              </div>

              {/* Patient */}
              <div>
                <span className="text-sm font-medium text-gray-700">Paciente:</span>
                <div className="flex items-center mt-1">
                  <span className="mr-2">{getPatientTypeInfo(selectedAppointment).icon}</span>
                  <div>
                    <p className="font-medium">{selectedAppointment.patient_name}</p>
                    <p className={`text-sm ${getPatientTypeInfo(selectedAppointment).color}`}>
                      {getPatientTypeInfo(selectedAppointment).label}
                    </p>
                  </div>
                </div>
              </div>

              {/* Date and Time */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-sm font-medium text-gray-700">Data:</span>
                  <p className="flex items-center mt-1">
                    <Calendar className="h-4 w-4 mr-2 text-gray-400" />
                    {new Date(selectedAppointment.appointment_date).toLocaleDateString('pt-BR')}
                  </p>
                </div>
                <div>
                  <span className="text-sm font-medium text-gray-700">Hora:</span>
                  <p className="flex items-center mt-1">
                    <Clock className="h-4 w-4 mr-2 text-gray-400" />
                    {formatTime(selectedAppointment.appointment_time)}
                  </p>
                </div>
              </div>

              {/* Service */}
              <div>
                <span className="text-sm font-medium text-gray-700">Serviço:</span>
                <p className="mt-1">{selectedAppointment.service_name}</p>
              </div>

              {/* Value */}
              <div>
                <span className="text-sm font-medium text-gray-700">Valor:</span>
                <p className="flex items-center mt-1">
                  <DollarSign className="h-4 w-4 mr-2 text-gray-400" />
                  {formatCurrency(selectedAppointment.value)}
                </p>
              </div>

              {/* Location */}
              {selectedAppointment.location_name && (
                <div>
                  <span className="text-sm font-medium text-gray-700">Local:</span>
                  <p className="flex items-center mt-1">
                    <MapPin className="h-4 w-4 mr-2 text-gray-400" />
                    {selectedAppointment.location_name}
                  </p>
                  {selectedAppointment.location_address && (
                    <p className="text-sm text-gray-500 ml-6">
                      {selectedAppointment.location_address}
                    </p>
                  )}
                </div>
              )}

              {/* Notes */}
              {selectedAppointment.notes && (
                <div>
                  <span className="text-sm font-medium text-gray-700">Observações:</span>
                  <p className="mt-1 text-gray-600">{selectedAppointment.notes}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;