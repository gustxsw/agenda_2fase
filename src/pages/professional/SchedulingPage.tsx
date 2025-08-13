import React, { useState, useEffect } from 'react';
import { Calendar, Clock, User, Plus, Check, X, AlertCircle, ChevronLeft, ChevronRight, Users, MessageCircle } from 'lucide-react';
import { format, addDays, subDays, isSameDay } from 'date-fns';
import { ptBR } from 'date-fns/locale';

type Appointment = {
  id: number;
  date: string;
  time: string;
  client_name: string;
  client_phone?: string;
  service_name: string;
  status: 'scheduled' | 'confirmed' | 'completed' | 'cancelled';
  value: number;
  notes?: string;
  is_dependent: boolean;
};

type Service = {
  id: number;
  name: string;
  base_price: number;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
  phone?: string;
};

const SchedulingPage: React.FC = () => {
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [privatePatients, setPrivatePatients] = useState<PrivatePatient[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // New appointment modal
  const [showNewModal, setShowNewModal] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  
  // WhatsApp modal
  const [showWhatsAppModal, setShowWhatsAppModal] = useState(false);
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  const [whatsappMessage, setWhatsappMessage] = useState('');
  
  // Form state
  const [formData, setFormData] = useState({
    patient_type: 'convenio',
    client_cpf: '',
    private_patient_id: '',
    date: format(new Date(), 'yyyy-MM-dd'),
    time: '',
    service_id: '',
    value: '',
    notes: ''
  });

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
  }, [selectedDate]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      const dateStr = format(selectedDate, 'yyyy-MM-dd');
      
      console.log('🔄 Fetching data for date:', dateStr);
      
      // Fetch appointments using the enhanced endpoint
      const appointmentsResponse = await fetch(`${apiUrl}/api/consultations/scheduling?date=${dateStr}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (appointmentsResponse.ok) {
        const appointmentsData = await appointmentsResponse.json();
        console.log('✅ Appointments data:', appointmentsData);
        setAppointments(appointmentsData);
      } else {
        console.log('⚠️ Appointments endpoint not available, using fallback');
        // Fallback to regular consultations endpoint
        const fallbackResponse = await fetch(`${apiUrl}/api/consultations`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (fallbackResponse.ok) {
          const consultationsData = await fallbackResponse.json();
          const filteredAppointments = consultationsData
            .filter((consultation: any) => {
              const consultationDate = new Date(consultation.date);
              return isSameDay(consultationDate, selectedDate);
            })
            .map((consultation: any) => ({
              id: consultation.id,
              date: consultation.date,
              time: format(new Date(consultation.date), 'HH:mm'),
              client_name: consultation.client_name,
              client_phone: consultation.client_phone || null,
              service_name: consultation.service_name,
              status: consultation.status || 'completed',
              value: consultation.value,
              notes: consultation.notes || '',
              is_dependent: consultation.is_dependent || false
            }));
          
          setAppointments(filteredAppointments);
        }
      }
      
      // Fetch services
      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (servicesResponse.ok) {
        const servicesData = await servicesResponse.json();
        setServices(servicesData);
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
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados da agenda');
    } finally {
      setIsLoading(false);
    }
  };

  const updateStatus = async (appointmentId: number, newStatus: string) => {
    try {
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/consultations/${appointmentId}/status`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      });

      if (!response.ok) {
        // If endpoint doesn't exist, update locally
        console.log('⚠️ Status endpoint not available, updating locally');
      }

      // Update local state
      setAppointments(prev => prev.map(apt => 
        apt.id === appointmentId 
          ? { ...apt, status: newStatus as any }
          : apt
      ));

      setSuccess(`Status alterado para: ${getStatusInfo(newStatus).text}`);
      setTimeout(() => setSuccess(''), 3000);

      // If confirming and has phone, auto-open WhatsApp modal
      const appointment = appointments.find(a => a.id === appointmentId);
      if (newStatus === 'confirmed' && appointment?.client_phone) {
        setTimeout(() => openWhatsAppModal(appointment), 500);
      }
    } catch (error) {
      console.error('Error updating status:', error);
      setError('Erro ao atualizar status');
    }
  };

  const openWhatsAppModal = (appointment: Appointment) => {
    setSelectedAppointment(appointment);
    
    // Generate default message
    const appointmentDate = format(new Date(appointment.date), "dd/MM/yyyy", { locale: ptBR });
    const defaultMessage = `Olá ${appointment.client_name}! 👋

Sua consulta foi confirmada! ✅

📅 Data: ${appointmentDate}
⏰ Horário: ${appointment.time}
🏥 Serviço: ${appointment.service_name}
💰 Valor: ${formatCurrency(appointment.value)}

Aguardamos você! 😊

Convênio Quiro Ferreira
(64) 98124-9199`;

    setWhatsappMessage(defaultMessage);
    setShowWhatsAppModal(true);
  };

  const closeWhatsAppModal = () => {
    setShowWhatsAppModal(false);
    setSelectedAppointment(null);
    setWhatsappMessage('');
  };

  const sendWhatsAppMessage = () => {
    if (!selectedAppointment?.client_phone) return;

    // Clean phone number (remove formatting)
    const cleanPhone = selectedAppointment.client_phone.replace(/\D/g, '');
    
    // Add country code if not present
    const phoneWithCountry = cleanPhone.startsWith('55') ? cleanPhone : `55${cleanPhone}`;
    
    // Encode message for URL
    const encodedMessage = encodeURIComponent(whatsappMessage);
    
    // Open WhatsApp
    const whatsappUrl = `https://wa.me/${phoneWithCountry}?text=${encodedMessage}`;
    window.open(whatsappUrl, '_blank');
    
    closeWhatsAppModal();
    setSuccess('WhatsApp aberto! Mensagem enviada.');
    setTimeout(() => setSuccess(''), 3000);
  };

  const createAppointment = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    try {
      setIsCreating(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      let clientData = null;
      
      if (formData.patient_type === 'convenio') {
        // Search client by CPF
        const clientResponse = await fetch(`${apiUrl}/api/clients/lookup?cpf=${formData.client_cpf}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!clientResponse.ok) {
          throw new Error('Cliente não encontrado');
        }
        
        clientData = await clientResponse.json();
        
        if (clientData.subscription_status !== 'active') {
          throw new Error('Cliente não possui assinatura ativa');
        }
      }
      
      // Create consultation
      const consultationData = {
        client_id: formData.patient_type === 'convenio' ? clientData.id : null,
        private_patient_id: formData.patient_type === 'private' ? parseInt(formData.private_patient_id) : null,
        service_id: parseInt(formData.service_id),
        value: parseFloat(formData.value),
        date: new Date(`${formData.date}T${formData.time}`).toISOString(),
        status: 'scheduled',
        notes: formData.notes
      };
      
      console.log('🔄 Creating consultation:', consultationData);
      
      const response = await fetch(`${apiUrl}/api/consultations`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(consultationData)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao criar agendamento');
      }
      
      await fetchData();
      setShowNewModal(false);
      setFormData({
        patient_type: 'convenio',
        client_cpf: '',
        private_patient_id: '',
        date: format(new Date(), 'yyyy-MM-dd'),
        time: '',
        service_id: '',
        value: '',
        notes: ''
      });
      
      setSuccess('Consulta agendada com sucesso!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao criar agendamento');
    } finally {
      setIsCreating(false);
    }
  };

  const getStatusInfo = (status: string) => {
    switch (status) {
      case 'scheduled':
        return { text: 'Agendado', className: 'bg-blue-100 text-blue-800' };
      case 'confirmed':
        return { text: 'Confirmado', className: 'bg-green-100 text-green-800' };
      case 'completed':
        return { text: 'Concluído', className: 'bg-gray-100 text-gray-800' };
      case 'cancelled':
        return { text: 'Cancelado', className: 'bg-red-100 text-red-800' };
      default:
        return { text: 'Agendado', className: 'bg-blue-100 text-blue-800' };
    }
  };

  const getAvailableActions = (appointment: Appointment) => {
    const actions = [];
    
    switch (appointment.status) {
      case 'scheduled':
        actions.push(
          { 
            action: () => updateStatus(appointment.id, 'confirmed'), 
            label: 'Confirmar', 
            icon: <Check className="h-4 w-4" />, 
            className: 'text-green-600 hover:bg-green-50' 
          },
          { 
            action: () => updateStatus(appointment.id, 'cancelled'), 
            label: 'Cancelar', 
            icon: <X className="h-4 w-4" />, 
            className: 'text-red-600 hover:bg-red-50' 
          }
        );
        break;
      case 'confirmed':
        actions.push(
          { 
            action: () => updateStatus(appointment.id, 'completed'), 
            label: 'Concluir', 
            icon: <Check className="h-4 w-4" />, 
            className: 'text-gray-600 hover:bg-gray-50' 
          },
          { 
            action: () => updateStatus(appointment.id, 'cancelled'), 
            label: 'Cancelar', 
            icon: <X className="h-4 w-4" />, 
            className: 'text-red-600 hover:bg-red-50' 
          }
        );
        
        // Add WhatsApp button if phone is available
        if (appointment.client_phone) {
          actions.push({
            action: () => openWhatsAppModal(appointment),
            label: 'WhatsApp',
            icon: <MessageCircle className="h-4 w-4" />,
            className: 'text-green-600 hover:bg-green-50'
          });
        }
        break;
      case 'completed':
      case 'cancelled':
        actions.push({
          action: () => updateStatus(appointment.id, 'scheduled'),
          label: 'Reagendar',
          icon: <Calendar className="h-4 w-4" />,
          className: 'text-blue-600 hover:bg-blue-50'
        });
        break;
    }
    
    return actions;
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    return numericValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
  };

  const handleServiceChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const serviceId = e.target.value;
    setFormData(prev => ({ ...prev, service_id: serviceId }));
    
    // Auto-fill value based on service
    const service = services.find(s => s.id.toString() === serviceId);
    if (service) {
      setFormData(prev => ({ ...prev, value: service.base_price.toString() }));
    }
  };

  const generateTimeSlots = () => {
    const slots = [];
    for (let hour = 8; hour <= 18; hour++) {
      for (let minute = 0; minute < 60; minute += 30) {
        const timeStr = `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`;
        slots.push(timeStr);
      }
    }
    return slots;
  };

  const timeSlots = generateTimeSlots();
  const dailyAppointments = appointments.sort((a, b) => a.time.localeCompare(b.time));

  // Statistics
  const stats = {
    scheduled: dailyAppointments.filter(a => a.status === 'scheduled').length,
    confirmed: dailyAppointments.filter(a => a.status === 'confirmed').length,
    completed: dailyAppointments.filter(a => a.status === 'completed').length,
    cancelled: dailyAppointments.filter(a => a.status === 'cancelled').length
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda</h1>
          <p className="text-gray-600">Visualize e gerencie seus agendamentos</p>
        </div>
        
        <button
          onClick={() => setShowNewModal(true)}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Nova Consulta
        </button>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 flex items-center">
          <AlertCircle className="h-5 w-5 mr-2" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6 flex items-center">
          <Check className="h-5 w-5 mr-2" />
          {success}
        </div>
      )}

      {/* Date Navigation */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setSelectedDate(subDays(selectedDate, 1))}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronLeft className="h-5 w-5" />
          </button>
          
          <div className="text-center">
            <h2 className="text-xl font-semibold text-gray-900">
              {format(selectedDate, "EEEE, dd 'de' MMMM", { locale: ptBR })}
            </h2>
            <p className="text-sm text-gray-600">
              {dailyAppointments.length} agendamento(s)
            </p>
          </div>
          
          <button
            onClick={() => setSelectedDate(addDays(selectedDate, 1))}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <ChevronRight className="h-5 w-5" />
          </button>
        </div>
        
        <div className="flex justify-center mt-4">
          <button
            onClick={() => setSelectedDate(new Date())}
            className="btn btn-secondary"
          >
            Hoje
          </button>
        </div>
      </div>

      {/* Daily Statistics */}
      {dailyAppointments.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
          <div className="bg-blue-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-blue-600">{stats.scheduled}</div>
            <div className="text-sm text-blue-700">Agendados</div>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-green-600">{stats.confirmed}</div>
            <div className="text-sm text-green-700">Confirmados</div>
          </div>
          
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-gray-600">{stats.completed}</div>
            <div className="text-sm text-gray-700">Concluídos</div>
          </div>
          
          <div className="bg-red-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-red-600">{stats.cancelled}</div>
            <div className="text-sm text-red-700">Cancelados</div>
          </div>
        </div>
      )}

      {/* Appointments List */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando agendamentos...</p>
          </div>
        ) : dailyAppointments.length === 0 ? (
          <div className="text-center py-12">
            <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              Nenhum agendamento para este dia
            </h3>
            <p className="text-gray-600 mb-4">
              Sua agenda está livre para {format(selectedDate, "dd 'de' MMMM", { locale: ptBR })}
            </p>
            <button
              onClick={() => setShowNewModal(true)}
              className="btn btn-primary inline-flex items-center"
            >
              <Plus className="h-5 w-5 mr-2" />
              Criar Agendamento
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {dailyAppointments.map((appointment) => {
              const statusInfo = getStatusInfo(appointment.status);
              const actions = getAvailableActions(appointment);
              
              return (
                <div key={appointment.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {/* Time */}
                      <div className="text-center min-w-[80px]">
                        <div className="text-lg font-bold text-gray-900">
                          {appointment.time}
                        </div>
                        <Clock className="h-4 w-4 text-gray-400 mx-auto" />
                      </div>
                      
                      {/* Patient Info */}
                      <div className="flex-1">
                        <div className="flex items-center mb-1">
                          {appointment.is_dependent ? (
                            <Users className="h-4 w-4 text-blue-600 mr-2" />
                          ) : (
                            <User className="h-4 w-4 text-green-600 mr-2" />
                          )}
                          <span className="font-medium text-gray-900">
                            {appointment.client_name}
                          </span>
                          {appointment.is_dependent && (
                            <span className="ml-2 px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs">
                              Dependente
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-600 mb-1">
                          {appointment.service_name}
                        </p>
                        <p className="text-sm font-medium text-green-600">
                          {formatCurrency(appointment.value)}
                        </p>
                        {appointment.notes && (
                          <p className="text-sm text-gray-500 mt-1 italic">
                            "{appointment.notes}"
                          </p>
                        )}
                      </div>
                    </div>
                    
                    {/* Status and Actions */}
                    <div className="flex items-center space-x-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusInfo.className}`}>
                        {statusInfo.text}
                      </span>
                      
                      {/* Action buttons */}
                      <div className="flex items-center space-x-1">
                        {actions.map((action, index) => (
                          <button
                            key={index}
                            onClick={action.action}
                            className={`p-2 rounded-lg transition-colors ${action.className}`}
                            title={action.label}
                          >
                            {action.icon}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* New Appointment Modal */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold flex items-center">
                <Plus className="h-6 w-6 text-red-600 mr-2" />
                Nova Consulta
              </h2>
            </div>

            <form onSubmit={createAppointment} className="p-6">
              <div className="space-y-4">
                {/* Patient Type */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tipo de Paciente *
                  </label>
                  <select
                    value={formData.patient_type}
                    onChange={(e) => setFormData(prev => ({ 
                      ...prev, 
                      patient_type: e.target.value,
                      client_cpf: '',
                      private_patient_id: ''
                    }))}
                    className="input"
                    required
                  >
                    <option value="convenio">Cliente do Convênio</option>
                    <option value="private">Paciente Particular</option>
                  </select>
                </div>

                {/* Convenio Client */}
                {formData.patient_type === 'convenio' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      CPF do Cliente *
                    </label>
                    <input
                      type="text"
                      value={formatCpf(formData.client_cpf)}
                      onChange={(e) => setFormData(prev => ({ 
                        ...prev, 
                        client_cpf: e.target.value.replace(/\D/g, '') 
                      }))}
                      className="input"
                      placeholder="000.000.000-00"
                      required
                    />
                  </div>
                )}

                {/* Private Patient */}
                {formData.patient_type === 'private' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Paciente Particular *
                    </label>
                    <select
                      value={formData.private_patient_id}
                      onChange={(e) => setFormData(prev => ({ ...prev, private_patient_id: e.target.value }))}
                      className="input"
                      required
                    >
                      <option value="">Selecione um paciente</option>
                      {privatePatients.map(patient => (
                        <option key={patient.id} value={patient.id}>
                          {patient.name} - {formatCpf(patient.cpf)}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data *
                  </label>
                  <input
                    type="date"
                    value={formData.date}
                    onChange={(e) => setFormData(prev => ({ ...prev, date: e.target.value }))}
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Horário *
                  </label>
                  <select
                    value={formData.time}
                    onChange={(e) => setFormData(prev => ({ ...prev, time: e.target.value }))}
                    className="input"
                    required
                  >
                    <option value="">Selecione um horário</option>
                    {timeSlots.map(time => (
                      <option key={time} value={time}>{time}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Serviço *
                  </label>
                  <select
                    value={formData.service_id}
                    onChange={handleServiceChange}
                    className="input"
                    required
                  >
                    <option value="">Selecione um serviço</option>
                    {services.map(service => (
                      <option key={service.id} value={service.id}>
                        {service.name} - {formatCurrency(service.base_price)}
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
                    min="0"
                    step="0.01"
                    value={formData.value}
                    onChange={(e) => setFormData(prev => ({ ...prev, value: e.target.value }))}
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Observações
                  </label>
                  <textarea
                    value={formData.notes}
                    onChange={(e) => setFormData(prev => ({ ...prev, notes: e.target.value }))}
                    className="input min-h-[80px]"
                    placeholder="Observações sobre a consulta..."
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="btn btn-secondary"
                  disabled={isCreating}
                >
                  Cancelar
                </button>
                <button 
                  type="submit" 
                  className={`btn btn-primary ${isCreating ? 'opacity-70 cursor-not-allowed' : ''}`}
                  disabled={isCreating}
                >
                  {isCreating ? 'Criando...' : 'Agendar Consulta'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* WhatsApp Modal */}
      {showWhatsAppModal && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-lg">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold flex items-center">
                <MessageCircle className="h-6 w-6 text-green-600 mr-2" />
                Enviar WhatsApp
              </h2>
            </div>

            <div className="p-6">
              <div className="mb-4">
                <p className="text-gray-700 mb-2">
                  <span className="font-medium">Para:</span> {selectedAppointment.client_name}
                </p>
                <p className="text-gray-700 mb-2">
                  <span className="font-medium">Telefone:</span> {selectedAppointment.client_phone}
                </p>
                <p className="text-gray-700 mb-4">
                  <span className="font-medium">Horário:</span> {selectedAppointment.time} - {format(new Date(selectedAppointment.date), "dd/MM/yyyy")}
                </p>
              </div>
              
              <div className="mb-6">
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Mensagem (você pode editar):
                </label>
                <textarea
                  value={whatsappMessage}
                  onChange={(e) => setWhatsappMessage(e.target.value)}
                  className="input min-h-[150px] text-sm"
                  placeholder="Digite sua mensagem..."
                />
              </div>
              
              <div className="flex justify-end space-x-3">
                <button
                  onClick={closeWhatsAppModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button
                  onClick={sendWhatsAppMessage}
                  className="btn bg-green-600 text-white hover:bg-green-700 flex items-center"
                >
                  <MessageCircle className="h-4 w-4 mr-2" />
                  Enviar WhatsApp
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;