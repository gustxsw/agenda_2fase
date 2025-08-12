import React, { useState, useEffect } from 'react';
import { Calendar, Plus, Edit, Trash2, Clock, MapPin, User, Users, Search, Filter, X, Check, ChevronLeft, ChevronRight, MessageCircle, Phone, AlertCircle, Eye } from 'lucide-react';

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
  patient_phone?: string;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
  phone?: string;
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

const SchedulingPage: React.FC = () => {
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [filteredAppointments, setFilteredAppointments] = useState<Appointment[]>([]);
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [locations, setLocations] = useState<AttendanceLocation[]>([]);
  
  // Calendar state
  const [currentDate, setCurrentDate] = useState(new Date());
  const [selectedDate, setSelectedDate] = useState<Date | null>(null);
  const [viewMode, setViewMode] = useState<'calendar' | 'list'>('calendar');
  
  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  
  // Status update modal
  const [isStatusModalOpen, setIsStatusModalOpen] = useState(false);
  const [appointmentToUpdate, setAppointmentToUpdate] = useState<Appointment | null>(null);
  const [newStatus, setNewStatus] = useState('');
  
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

  // Status options with colors
  const statusOptions = [
    { value: 'scheduled', label: 'Agendado', color: 'bg-blue-500', bgColor: 'bg-blue-100', textColor: 'text-blue-800' },
    { value: 'confirmed', label: 'Confirmado', color: 'bg-green-500', bgColor: 'bg-green-100', textColor: 'text-green-800' },
    { value: 'completed', label: 'Realizado', color: 'bg-purple-500', bgColor: 'bg-purple-100', textColor: 'text-purple-800' },
    { value: 'cancelled', label: 'Cancelado', color: 'bg-red-500', bgColor: 'bg-red-100', textColor: 'text-red-800' },
    { value: 'no_show', label: 'Faltou', color: 'bg-yellow-500', bgColor: 'bg-yellow-100', textColor: 'text-yellow-800' },
    { value: 'rescheduled', label: 'Reagendado', color: 'bg-orange-500', bgColor: 'bg-orange-100', textColor: 'text-orange-800' }
  ];

  useEffect(() => {
    fetchData();
  }, [currentDate]);

  useEffect(() => {
    let filtered = appointments;

    if (searchTerm) {
      filtered = filtered.filter(apt =>
        apt.patient_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        apt.service_name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (statusFilter) {
      filtered = filtered.filter(apt => apt.status === statusFilter);
    }

    setFilteredAppointments(filtered);
  }, [appointments, searchTerm, statusFilter]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Get month range for current view
      const startOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
      const endOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0);
      
      const startDate = startOfMonth.toISOString().split('T')[0];
      const endDate = endOfMonth.toISOString().split('T')[0];

      // Fetch appointments
      const appointmentsResponse = await fetch(
        `${apiUrl}/api/scheduling/appointments?start_date=${startDate}&end_date=${endDate}`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      if (appointmentsResponse.ok) {
        const appointmentsData = await appointmentsResponse.json();
        setAppointments(appointmentsData);
      }

      // Fetch private patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        setPrivatePatients(patientsData);
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
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  // Calendar helper functions
  const getDaysInMonth = (date: Date) => {
    const year = date.getFullYear();
    const month = date.getMonth();
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const daysInMonth = lastDay.getDate();
    const startingDayOfWeek = firstDay.getDay();

    const days = [];
    
    // Add empty cells for days before the first day of the month
    for (let i = 0; i < startingDayOfWeek; i++) {
      days.push(null);
    }
    
    // Add all days of the month
    for (let day = 1; day <= daysInMonth; day++) {
      days.push(new Date(year, month, day));
    }
    
    return days;
  };

  const getAppointmentsForDate = (date: Date) => {
    const dateString = date.toISOString().split('T')[0];
    return filteredAppointments.filter(apt => apt.appointment_date === dateString);
  };

  const navigateMonth = (direction: 'prev' | 'next') => {
    const newDate = new Date(currentDate);
    if (direction === 'prev') {
      newDate.setMonth(newDate.getMonth() - 1);
    } else {
      newDate.setMonth(newDate.getMonth() + 1);
    }
    setCurrentDate(newDate);
  };

  const goToToday = () => {
    setCurrentDate(new Date());
    setSelectedDate(new Date());
  };

  const openCreateModal = (date?: Date) => {
    setModalMode('create');
    setFormData({
      private_patient_id: '',
      service_id: '',
      appointment_date: date ? date.toISOString().split('T')[0] : '',
      appointment_time: '',
      location_id: locations.find(loc => loc.is_default)?.id.toString() || '',
      notes: '',
      value: ''
    });
    setSelectedAppointment(null);
    setIsModalOpen(true);
  };

  const openEditModal = (appointment: Appointment) => {
    setModalMode('edit');
    setFormData({
      private_patient_id: appointment.private_patient_id?.toString() || '',
      service_id: '', // Would need to be determined from the appointment
      appointment_date: appointment.appointment_date,
      appointment_time: appointment.appointment_time,
      location_id: '', // Would need to be determined from the appointment
      notes: appointment.notes || '',
      value: appointment.value.toString()
    });
    setSelectedAppointment(appointment);
    setIsModalOpen(true);
  };

  const openStatusModal = (appointment: Appointment) => {
    setAppointmentToUpdate(appointment);
    setNewStatus(appointment.status);
    setIsStatusModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setIsStatusModalOpen(false);
    setError('');
    setSuccess('');
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const serviceId = e.target.value;
    setFormData(prev => ({ ...prev, service_id: serviceId }));
    
    // Auto-fill value based on service
    const selectedService = services.find(s => s.id.toString() === serviceId);
    if (selectedService) {
      setFormData(prev => ({ ...prev, value: selectedService.base_price.toString() }));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const url = modalMode === 'create' 
        ? `${apiUrl}/api/scheduling/appointments`
        : `${apiUrl}/api/scheduling/appointments/${selectedAppointment?.id}`;

      const method = modalMode === 'create' ? 'POST' : 'PUT';

      const response = await fetch(url, {
        method,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ...formData,
          private_patient_id: formData.private_patient_id ? parseInt(formData.private_patient_id) : null,
          service_id: parseInt(formData.service_id),
          location_id: formData.location_id ? parseInt(formData.location_id) : null,
          value: parseFloat(formData.value),
          status: 'scheduled' // Default status for new appointments
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao salvar agendamento');
      }

      setSuccess(modalMode === 'create' ? 'Agendamento criado com sucesso!' : 'Agendamento atualizado com sucesso!');
      await fetchData();

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao salvar agendamento');
    }
  };

  const updateAppointmentStatus = async () => {
    if (!appointmentToUpdate) return;

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/scheduling/appointments/${appointmentToUpdate.id}/status`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao atualizar status');
      }

      setSuccess('Status atualizado com sucesso!');
      await fetchData();
      setIsStatusModalOpen(false);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao atualizar status');
    }
  };

  const sendWhatsAppMessage = (appointment: Appointment) => {
    const phone = appointment.patient_phone?.replace(/\D/g, '');
    if (!phone) {
      setError('Número de telefone não encontrado para este paciente');
      return;
    }

    const date = new Date(appointment.appointment_date).toLocaleDateString('pt-BR');
    const time = appointment.appointment_time.slice(0, 5);
    
    const message = `Olá ${appointment.patient_name}! 👋

Confirmação de Consulta - Convênio Quiro Ferreira

📅 Data: ${date}
🕐 Horário: ${time}
🏥 Serviço: ${appointment.service_name}
📍 Local: ${appointment.location_name || 'A definir'}

Por favor, confirme sua presença respondendo esta mensagem.

Em caso de necessidade de reagendamento, entre em contato conosco com antecedência.

Obrigado! 🙏`;

    const whatsappUrl = `https://wa.me/55${phone}?text=${encodeURIComponent(message)}`;
    window.open(whatsappUrl, '_blank');
  };

  const sendConfirmationMessage = (appointment: Appointment) => {
    const phone = appointment.patient_phone?.replace(/\D/g, '');
    if (!phone) {
      setError('Número de telefone não encontrado para este paciente');
      return;
    }

    const date = new Date(appointment.appointment_date).toLocaleDateString('pt-BR');
    const time = appointment.appointment_time.slice(0, 5);
    
    // Get professional name from user context
    const professionalName = user?.name || 'Profissional';
    
    const message = `Olá ${appointment.patient_name}, gostaria de confirmar o seu atendimento com ${professionalName} às ${time} do dia ${date}.`;

    const whatsappUrl = `https://wa.me/55${phone}?text=${encodeURIComponent(message)}`;
    window.open(whatsappUrl, '_blank');
  };

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
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/scheduling/appointments/${appointmentToDelete.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao excluir agendamento');
      }

      await fetchData();
      setSuccess('Agendamento excluído com sucesso!');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao excluir agendamento');
    } finally {
      setAppointmentToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
  };

  const formatTime = (timeString: string) => {
    return timeString.slice(0, 5); // HH:MM
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };

  const getStatusInfo = (status: string) => {
    return statusOptions.find(s => s.value === status) || statusOptions[0];
  };

  const monthNames = [
    'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
    'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'
  ];

  const dayNames = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];

  const days = getDaysInMonth(currentDate);

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda de Atendimentos</h1>
          <p className="text-gray-600">Gerencie seus agendamentos de pacientes particulares</p>
        </div>
        
        <div className="flex items-center space-x-3">
          <div className="flex bg-gray-100 rounded-lg p-1">
            <button
              onClick={() => setViewMode('calendar')}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'calendar' 
                  ? 'bg-white text-gray-900 shadow-sm' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <Calendar className="h-4 w-4 mr-2 inline" />
              Calendário
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                viewMode === 'list' 
                  ? 'bg-white text-gray-900 shadow-sm' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              <Filter className="h-4 w-4 mr-2 inline" />
              Lista
            </button>
          </div>
          
          <button
            onClick={() => openCreateModal()}
            className="btn btn-primary flex items-center"
          >
            <Plus className="h-5 w-5 mr-2" />
            Novo Agendamento
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar paciente ou serviço..."
              className="input pl-10"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input"
          >
            <option value="">Todos os status</option>
            {statusOptions.map((status) => (
              <option key={status.value} value={status.value}>
                {status.label}
              </option>
            ))}
          </select>

          <button
            onClick={() => {
              setSearchTerm('');
              setStatusFilter('');
            }}
            className="btn btn-secondary"
          >
            Limpar Filtros
          </button>
        </div>
      </div>

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
      {viewMode === 'calendar' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          {/* Calendar Header */}
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center space-x-4">
              <h2 className="text-xl font-semibold text-gray-900">
                {monthNames[currentDate.getMonth()]} {currentDate.getFullYear()}
              </h2>
              <button
                onClick={goToToday}
                className="btn btn-outline text-sm"
              >
                Hoje
              </button>
            </div>
            
            <div className="flex items-center space-x-2">
              <button
                onClick={() => navigateMonth('prev')}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <ChevronLeft className="h-5 w-5 text-gray-600" />
              </button>
              <button
                onClick={() => navigateMonth('next')}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <ChevronRight className="h-5 w-5 text-gray-600" />
              </button>
            </div>
          </div>

          {/* Calendar Grid */}
          <div className="grid grid-cols-7 gap-1 mb-4">
            {dayNames.map((day) => (
              <div key={day} className="p-3 text-center text-sm font-medium text-gray-500 bg-gray-50 rounded-lg">
                {day}
              </div>
            ))}
          </div>

          <div className="grid grid-cols-7 gap-1">
            {days.map((day, index) => {
              if (!day) {
                return <div key={index} className="h-32 p-1"></div>;
              }

              const dayAppointments = getAppointmentsForDate(day);
              const isToday = day.toDateString() === new Date().toDateString();
              const isSelected = selectedDate?.toDateString() === day.toDateString();

              return (
                <div
                  key={index}
                  className={`h-32 p-2 border border-gray-100 rounded-lg cursor-pointer transition-all duration-200 hover:bg-gray-50 hover:shadow-md ${
                    isToday ? 'bg-red-50 border-red-200 shadow-sm' : ''
                  } ${isSelected ? 'bg-blue-50 border-blue-300 shadow-md' : ''}`}
                  onClick={() => setSelectedDate(day)}
                  onDoubleClick={() => openCreateModal(day)}
                >
                  <div className={`text-sm font-medium mb-2 ${
                    isToday ? 'text-red-600' : 'text-gray-900'
                  }`}>
                    {day.getDate()}
                  </div>
                  
                  <div className="space-y-1">
                    {dayAppointments.slice(0, 3).map((apt) => {
                      const statusInfo = getStatusInfo(apt.status);
                      return (
                        <div
                          key={apt.id}
                          className={`text-xs p-1.5 rounded-md truncate cursor-pointer transition-all duration-200 hover:scale-105 ${statusInfo.bgColor} ${statusInfo.textColor} border border-opacity-20`}
                          title={`${apt.patient_name} - ${formatTime(apt.appointment_time)} - ${apt.service_name}`}
                          onClick={(e) => {
                            e.stopPropagation();
                            openStatusModal(apt);
                          }}
                        >
                          <div className="flex items-center space-x-1">
                            <div className={`w-2 h-2 rounded-full ${statusInfo.color}`}></div>
                            <span className="font-medium">{formatTime(apt.appointment_time)}</span>
                          </div>
                          <div className="truncate">{apt.patient_name}</div>
                        </div>
                      );
                    })}
                    {dayAppointments.length > 3 && (
                      <div className="text-xs text-gray-500 text-center bg-gray-100 rounded-md p-1">
                        +{dayAppointments.length - 3} mais
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Date Details */}
          {selectedDate && (
            <div className="mt-6 p-6 bg-gradient-to-r from-gray-50 to-blue-50 rounded-xl border border-gray-200">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                  <Calendar className="h-5 w-5 text-blue-600 mr-2" />
                  {selectedDate.toLocaleDateString('pt-BR', { 
                    weekday: 'long', 
                    year: 'numeric', 
                    month: 'long', 
                    day: 'numeric' 
                  })}
                </h3>
                <button
                  onClick={() => openCreateModal(selectedDate)}
                  className="btn btn-primary btn-sm flex items-center"
                >
                  <Plus className="h-4 w-4 mr-1" />
                  Agendar
                </button>
              </div>
              
              {getAppointmentsForDate(selectedDate).length === 0 ? (
                <div className="text-center py-8">
                  <Calendar className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                  <p className="text-gray-600 mb-3">Nenhum agendamento para este dia</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {getAppointmentsForDate(selectedDate)
                    .sort((a, b) => a.appointment_time.localeCompare(b.appointment_time))
                    .map((apt) => {
                      const statusInfo = getStatusInfo(apt.status);
                      return (
                        <div key={apt.id} className="flex items-center justify-between p-4 bg-white rounded-lg border border-gray-200 shadow-sm hover:shadow-md transition-all duration-200">
                          <div className="flex-1">
                            <div className="flex items-center space-x-3">
                              <div className={`w-4 h-4 rounded-full ${statusInfo.color} flex-shrink-0`}></div>
                              <div>
                                <div className="flex items-center space-x-2">
                                  <p className="font-medium text-gray-900">{apt.patient_name}</p>
                                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusInfo.bgColor} ${statusInfo.textColor}`}>
                                    {statusInfo.label}
                                  </span>
                                </div>
                                <p className="text-sm text-gray-600 flex items-center mt-1">
                                  <Clock className="h-3 w-3 mr-1" />
                                  {formatTime(apt.appointment_time)} - {apt.service_name}
                                </p>
                                {apt.location_name && (
                                  <p className="text-sm text-gray-500 flex items-center mt-1">
                                    <MapPin className="h-3 w-3 mr-1" />
                                    {apt.location_name}
                                  </p>
                                )}
                                <p className="text-sm font-medium text-green-600 mt-1">
                                  {formatCurrency(apt.value)}
                                </p>
                              </div>
                            </div>
                          </div>
                          
                          <div className="flex items-center space-x-2">
                            {apt.patient_phone && (
                              <>
                                <button
                                  onClick={() => sendConfirmationMessage(apt)}
                                  className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                                  title="Confirmar Presença"
                                >
                                  <Phone className="h-4 w-4" />
                                </button>
                                
                                <button
                                  onClick={() => sendWhatsAppMessage(apt)}
                                  className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                                  title="Mensagem Completa"
                                >
                                  <MessageCircle className="h-4 w-4" />
                                </button>
                              </>
                            )}
                            
                            <button
                              onClick={() => openStatusModal(apt)}
                              className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                              title="Alterar Status"
                            >
                              <Clock className="h-4 w-4" />
                            </button>
                            
                            <button
                              onClick={() => openEditModal(apt)}
                              className="p-2 text-gray-600 hover:bg-gray-50 rounded-lg transition-colors"
                              title="Editar"
                            >
                              <Edit className="h-4 w-4" />
                            </button>
                            
                            <button
                              onClick={() => confirmDelete(apt)}
                              className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                              title="Excluir"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </div>
                      );
                    })}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* List View */}
      {viewMode === 'list' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100">
          {isLoading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Carregando agendamentos...</p>
            </div>
          ) : filteredAppointments.length === 0 ? (
            <div className="text-center py-12">
              <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                {searchTerm || statusFilter ? 'Nenhum agendamento encontrado' : 'Nenhum agendamento cadastrado'}
              </h3>
              <p className="text-gray-600 mb-4">
                {searchTerm || statusFilter
                  ? 'Tente ajustar os filtros de busca.'
                  : 'Comece criando seu primeiro agendamento de paciente particular.'
                }
              </p>
              {!searchTerm && !statusFilter && (
                <button
                  onClick={() => openCreateModal()}
                  className="btn btn-primary inline-flex items-center"
                >
                  <Plus className="h-5 w-5 mr-2" />
                  Criar Primeiro Agendamento
                </button>
              )}
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Paciente
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Data/Hora
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Serviço
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Local
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Valor
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Ações
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredAppointments.map((appointment) => {
                    const statusInfo = getStatusInfo(appointment.status);
                    return (
                      <tr key={appointment.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-10 w-10">
                              <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                                <User className="h-5 w-5 text-red-600" />
                              </div>
                            </div>
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900">
                                {appointment.patient_name}
                              </div>
                              <div className="text-sm text-gray-500">
                                CPF: {appointment.patient_cpf?.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')}
                              </div>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {formatDate(appointment.appointment_date)}
                          </div>
                          <div className="text-sm text-gray-500">
                            {formatTime(appointment.appointment_time)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {appointment.service_name}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {appointment.location_name || 'Não informado'}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm font-medium text-gray-900">
                            {formatCurrency(appointment.value)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <button
                            onClick={() => openStatusModal(appointment)}
                            className={`px-3 py-1 text-xs font-medium rounded-full transition-colors hover:opacity-80 ${statusInfo.bgColor} ${statusInfo.textColor}`}
                          >
                            {statusInfo.label}
                          </button>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <div className="flex items-center justify-end space-x-2">
                            {appointment.patient_phone && (
                              <>
                                <button
                                  onClick={() => sendConfirmationMessage(appointment)}
                                  className="text-blue-600 hover:text-blue-900"
                                  title="Confirmar Presença"
                                >
                                  <Phone className="h-4 w-4" />
                                </button>
                                
                                <button
                                  onClick={() => sendWhatsAppMessage(appointment)}
                                  className="text-green-600 hover:text-green-900"
                                  title="Mensagem Completa"
                                >
                                  <MessageCircle className="h-4 w-4" />
                                </button>
                              </>
                            )}
                            
                            <button
                              onClick={() => openStatusModal(appointment)}
                              className="text-blue-600 hover:text-blue-900"
                              title="Alterar Status"
                            >
                              <Clock className="h-4 w-4" />
                            </button>
                            
                            <button
                              onClick={() => openEditModal(appointment)}
                              className="text-gray-600 hover:text-gray-900"
                              title="Editar"
                            >
                              <Edit className="h-4 w-4" />
                            </button>
                            
                            <button
                              onClick={() => confirmDelete(appointment)}
                              className="text-red-600 hover:text-red-900"
                              title="Excluir"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Status Legend */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mt-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <Eye className="h-5 w-5 text-red-600 mr-2" />
          Legenda de Status e Ações
        </h3>
        
        {/* Status Legend */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {statusOptions.map((status) => (
            <div key={status.value} className="flex items-center space-x-2 p-2 rounded-lg hover:bg-gray-50 transition-colors">
              <div className={`w-4 h-4 rounded-full ${status.color}`}></div>
              <span className="text-sm text-gray-700 font-medium">{status.label}</span>
            </div>
          ))}
        </div>
        
        {/* Actions Legend */}
        <div className="mt-6 border-t border-gray-200 pt-4">
          <h4 className="text-md font-semibold text-gray-900 mb-3">Ações Disponíveis</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="flex items-center space-x-2 p-2 rounded-lg bg-blue-50">
              <Phone className="h-4 w-4 text-blue-600" />
              <span className="text-sm text-blue-700 font-medium">Confirmar Presença</span>
            </div>
            <div className="flex items-center space-x-2 p-2 rounded-lg bg-green-50">
              <MessageCircle className="h-4 w-4 text-green-600" />
              <span className="text-sm text-green-700 font-medium">Mensagem Completa</span>
            </div>
            <div className="flex items-center space-x-2 p-2 rounded-lg bg-gray-50">
              <Clock className="h-4 w-4 text-gray-600" />
              <span className="text-sm text-gray-700 font-medium">Alterar Status</span>
            </div>
            <div className="flex items-center space-x-2 p-2 rounded-lg bg-red-50">
              <Edit className="h-4 w-4 text-red-600" />
              <span className="text-sm text-red-700 font-medium">Editar/Excluir</span>
            </div>
          </div>
        </div>
        
        <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <div className="space-y-2">
            <p className="text-sm text-blue-700">
              💡 <strong>Dicas de Uso:</strong>
            </p>
            <ul className="text-sm text-blue-600 space-y-1 ml-4">
              <li>• Clique nos agendamentos do calendário para alterar o status rapidamente</li>
              <li>• Use <strong>Confirmar Presença</strong> (📞) para enviar mensagem rápida de confirmação</li>
              <li>• Use <strong>Mensagem Completa</strong> (💬) para enviar detalhes completos da consulta</li>
              <li>• Clique duplo em um dia vazio para criar novo agendamento</li>
            </ul>
          </div>
        </div>
      </div>

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

      {/* Status update modal */}
      {isStatusModalOpen && appointmentToUpdate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold flex items-center">
                <Clock className="h-6 w-6 text-blue-600 mr-2" />
                Alterar Status
              </h2>
              <button
                onClick={closeModal}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="mb-6 p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center mb-2">
                <User className="h-4 w-4 text-gray-600 mr-2" />
                <span className="font-medium text-gray-900">{appointmentToUpdate.patient_name}</span>
              </div>
              <div className="flex items-center text-sm text-gray-600">
                <Calendar className="h-3 w-3 mr-1" />
                {formatDate(appointmentToUpdate.appointment_date)} às {formatTime(appointmentToUpdate.appointment_time)}
              </div>
              <div className="text-sm text-gray-600 mt-1">
                {appointmentToUpdate.service_name} - {formatCurrency(appointmentToUpdate.value)}
              </div>
            </div>

            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-3">
                Novo Status
              </label>
              <div className="space-y-2">
                {statusOptions.map((status) => (
                  <label key={status.value} className="flex items-center p-3 rounded-lg border border-gray-200 hover:bg-gray-50 cursor-pointer transition-colors">
                    <input
                      type="radio"
                      name="status"
                      value={status.value}
                      checked={newStatus === status.value}
                      onChange={(e) => setNewStatus(e.target.value)}
                      className="mr-3"
                    />
                    <div className="flex items-center">
                      <div className={`w-4 h-4 rounded-full ${status.color} mr-3`}></div>
                      <span className="text-sm font-medium text-gray-700">{status.label}</span>
                    </div>
                  </label>
                ))}
              </div>
            </div>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={closeModal}
                className="btn btn-secondary"
              >
                Cancelar
              </button>
              <button
                onClick={updateAppointmentStatus}
                className="btn btn-primary"
                disabled={!newStatus || newStatus === appointmentToUpdate.status}
              >
                Atualizar Status
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && appointmentToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <AlertCircle className="h-6 w-6 text-red-600 mr-2" />
              Confirmar Exclusão
            </h2>
            
            <div className="mb-6 p-4 bg-red-50 rounded-lg">
              <p className="text-red-800 mb-2">
                <strong>Paciente:</strong> {appointmentToDelete.patient_name}
              </p>
              <p className="text-red-800">
                <strong>Data/Hora:</strong> {formatDate(appointmentToDelete.appointment_date)} às {formatTime(appointmentToDelete.appointment_time)}
              </p>
            </div>
            
            <p className="mb-6 text-gray-700">
              Tem certeza que deseja excluir este agendamento? Esta ação não pode ser desfeita.
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
                Confirmar Exclusão
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;