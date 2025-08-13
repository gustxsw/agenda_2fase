import React, { useState, useEffect } from 'react';
import { Calendar, Clock, User, Plus, Check, X, AlertCircle, ChevronLeft, ChevronRight, Users } from 'lucide-react';
import { format, addDays, subDays, isSameDay } from 'date-fns';
import { ptBR } from 'date-fns/locale';

type Appointment = {
  id: number;
  date: string;
  time: string;
  client_name: string;
  service_name: string;
  status: 'scheduled' | 'confirmed' | 'completed' | 'cancelled';
  value: number;
  notes?: string;
  is_dependent: boolean;
  client_phone?: string;
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
  
  // Status change modal
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  const [newStatus, setNewStatus] = useState<string>('');
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  
  // WhatsApp modal
  const [showWhatsAppModal, setShowWhatsAppModal] = useState(false);
  const [whatsappMessage, setWhatsappMessage] = useState('');
  
  // Form state
  const [formData, setFormData] = useState({
    patient_type: 'convenio', // 'convenio' or 'private'
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
      
      console.log('🔄 Fetching appointments for date:', dateStr);
      
      // Fetch appointments - usando endpoint simples
      const appointmentsResponse = await fetch(`${apiUrl}/api/consultations`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (appointmentsResponse.ok) {
        const appointmentsData = await appointmentsResponse.json();
        console.log('✅ Appointments data:', appointmentsData);
        
        // Filter by selected date and convert to appointment format
        const filteredAppointments = appointmentsData
          .filter((consultation: any) => {
            const consultationDate = new Date(consultation.date);
            return isSameDay(consultationDate, selectedDate);
          })
          .map((consultation: any) => ({
            id: consultation.id,
            date: consultation.date,
            time: format(new Date(consultation.date), 'HH:mm'),
            client_name: consultation.client_name,
            service_name: consultation.service_name,
            status: 'completed', // Consultas já registradas são consideradas concluídas
            value: consultation.value,
            notes: '',
            is_dependent: consultation.is_dependent || false,
            client_phone: consultation.client_phone
          }));
        
        setAppointments(filteredAppointments);
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

  const openStatusModal = (appointment: Appointment, status: string) => {
    setSelectedAppointment(appointment);
    setNewStatus(status);
    setShowStatusModal(true);
  };

  const closeStatusModal = () => {
    setShowStatusModal(false);
    setSelectedAppointment(null);
    setNewStatus('');
  };

  const updateAppointmentStatus = async () => {
    if (!selectedAppointment || !newStatus) return;

    try {
      setIsUpdatingStatus(true);
      setError('');

      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/consultations/${selectedAppointment.id}/status`, {
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

      // Update local state
      setAppointments(prev => prev.map(apt => 
        apt.id === selectedAppointment.id 
          ? { ...apt, status: newStatus as any }
          : apt
      ));

      setSuccess('Status atualizado com sucesso!');
      setTimeout(() => setSuccess(''), 3000);
      
      closeStatusModal();

      // If confirming and has phone, show WhatsApp modal
      if (newStatus === 'confirmed' && selectedAppointment.client_phone) {
        openWhatsAppModal(selectedAppointment);
      }
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao atualizar status');
    } finally {
      setIsUpdatingStatus(false);
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
    setSuccess('WhatsApp aberto! Mensagem pronta para envio.');
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
      
      // Se for convênio, buscar cliente por CPF
      if (formData.patient_type === 'convenio') {
        const clientResponse = await fetch(`${apiUrl}/api/clients/lookup?cpf=${formData.client_cpf.replace(/\D/g, '')}`, {
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
      
      // Criar consulta diretamente
      const consultationData = {
        client_id: formData.patient_type === 'convenio' ? clientData.id : null,
        private_patient_id: formData.patient_type === 'private' ? parseInt(formData.private_patient_id) : null,
        service_id: parseInt(formData.service_id),
        value: parseFloat(formData.value),
        date: new Date(`${formData.date}T${formData.time}`).toISOString()
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
        date: format(selectedDate, 'yyyy-MM-dd'),
        time: '',
        service_id: '',
        value: '',
        notes: ''
      });
      setSuccess('Consulta registrada com sucesso!');
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
        return { text: 'Agendado', className: 'bg-blue-100 text-blue-800', color: 'blue' };
      case 'confirmed':
        return { text: 'Confirmado', className: 'bg-green-100 text-green-800', color: 'green' };
      case 'completed':
        return { text: 'Concluído', className: 'bg-gray-100 text-gray-800', color: 'gray' };
      case 'cancelled':
        return { text: 'Cancelado', className: 'bg-red-100 text-red-800', color: 'red' };
      default:
        return { text: status, className: 'bg-gray-100 text-gray-800', color: 'gray' };
    }
  };

  const getAvailableActions = (status: string) => {
    switch (status) {
      case 'scheduled':
        return [
          { status: 'confirmed', label: 'Confirmar', color: 'green', icon: <Check className="h-4 w-4" /> },
          { status: 'cancelled', label: 'Cancelar', color: 'red', icon: <X className="h-4 w-4" /> }
        ];
      case 'confirmed':
        return [
          { status: 'completed', label: 'Concluir', color: 'gray', icon: <Check className="h-4 w-4" /> },
          { status: 'cancelled', label: 'Cancelar', color: 'red', icon: <X className="h-4 w-4" /> }
        ];
      case 'completed':
        return [
          { status: 'scheduled', label: 'Reagendar', color: 'blue', icon: <Calendar className="h-4 w-4" /> }
        ];
      case 'cancelled':
        return [
          { status: 'scheduled', label: 'Reagendar', color: 'blue', icon: <Calendar className="h-4 w-4" /> }
        ];
      default:
        return [];
    }
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

      {/* Navegação de Data */}
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

      {/* Lista de Agendamentos */}
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
              return (
                <div key={appointment.id} className="p-6 hover:bg-gray-50 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      {/* Horário */}
                      <div className="text-center min-w-[80px]">
                        <div className="text-lg font-bold text-gray-900">
                          {appointment.time}
                        </div>
                        <Clock className="h-4 w-4 text-gray-400 mx-auto" />
                      </div>
                      
                      {/* Informações do paciente */}
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
                    
                    {/* Status */}
                    <div className="flex items-center space-x-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusInfo.className}`}>
                        {statusInfo.text}
                      </span>
                      
                      {/* Action buttons */}
                      <div className="flex items-center space-x-1">
                        {getAvailableActions(appointment.status).map((action) => (
                          <button
                            key={action.status}
                            onClick={() => openStatusModal(appointment, action.status)}
                            className={`p-2 rounded-lg transition-colors ${
                              action.color === 'green' ? 'text-green-600 hover:bg-green-50' :
                              action.color === 'red' ? 'text-red-600 hover:bg-red-50' :
                              action.color === 'blue' ? 'text-blue-600 hover:bg-blue-50' :
                              'text-gray-600 hover:bg-gray-50'
                            }`}
                            title={action.label}
                          >
                            {action.icon}
                          </button>
                        ))}
                        
                        {/* WhatsApp button for confirmed appointments */}
                        {appointment.status === 'confirmed' && appointment.client_phone && (
                          <button
                            onClick={() => openWhatsAppModal(appointment)}
                            className="p-2 text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                            title="Enviar WhatsApp"
                          >
                            <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
                              <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893A11.821 11.821 0 0020.885 3.488"/>
                            </svg>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Estatísticas do Dia */}
      {dailyAppointments.length > 0 && (
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-blue-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-blue-600">
              {dailyAppointments.filter(a => a.status === 'scheduled').length}
            </div>
            <div className="text-sm text-blue-700">Agendados</div>
          </div>
          
          <div className="bg-green-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-green-600">
              {dailyAppointments.filter(a => a.status === 'confirmed').length}
            </div>
            <div className="text-sm text-green-700">Confirmados</div>
          </div>
          
          <div className="bg-gray-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-gray-600">
              {dailyAppointments.filter(a => a.status === 'completed').length}
            </div>
            <div className="text-sm text-gray-700">Concluídos</div>
          </div>
          
          <div className="bg-red-50 p-4 rounded-lg text-center">
            <div className="text-2xl font-bold text-red-600">
              {dailyAppointments.filter(a => a.status === 'cancelled').length}
            </div>
            <div className="text-sm text-red-700">Cancelados</div>
          </div>
        </div>
      )}

      {/* Modal de Nova Consulta */}
      {showNewModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold flex items-center">
                <Plus className="h-6 w-6 text-red-600 mr-2" />
                Nova Consulta
              </h2>
            </div>

            {error && (
              <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg">
                {error}
              </div>
            )}

            <form onSubmit={createAppointment} className="p-6">
              <div className="space-y-4">
                {/* Tipo de Paciente */}
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

                {/* Cliente do Convênio */}
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

                {/* Paciente Particular */}
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
                  {isCreating ? 'Criando...' : 'Registrar Consulta'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Status Change Modal */}
      {showStatusModal && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <Calendar className="h-6 w-6 text-red-600 mr-2" />
              Alterar Status
            </h2>
            
            <div className="mb-4">
              <p className="text-gray-700 mb-2">
                <span className="font-medium">Paciente:</span> {selectedAppointment.client_name}
              </p>
              <p className="text-gray-700 mb-2">
                <span className="font-medium">Serviço:</span> {selectedAppointment.service_name}
              </p>
              <p className="text-gray-700 mb-4">
                <span className="font-medium">Horário:</span> {selectedAppointment.time}
              </p>
              
              <div className="bg-gray-50 p-3 rounded-lg">
                <p className="text-sm text-gray-600">
                  Status atual: <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusInfo(selectedAppointment.status).className}`}>
                    {getStatusInfo(selectedAppointment.status).text}
                  </span>
                </p>
                <p className="text-sm text-gray-600 mt-1">
                  Novo status: <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusInfo(newStatus).className}`}>
                    {getStatusInfo(newStatus).text}
                  </span>
                </p>
              </div>
            </div>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={closeStatusModal}
                className="btn btn-secondary"
                disabled={isUpdatingStatus}
              >
                Cancelar
              </button>
              <button
                onClick={updateAppointmentStatus}
                className={`btn btn-primary ${isUpdatingStatus ? 'opacity-70 cursor-not-allowed' : ''}`}
                disabled={isUpdatingStatus}
              >
                {isUpdatingStatus ? 'Atualizando...' : 'Confirmar'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* WhatsApp Modal */}
      {showWhatsAppModal && selectedAppointment && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-lg p-6">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <svg className="h-6 w-6 text-green-600 mr-2" fill="currentColor" viewBox="0 0 24 24">
                <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893A11.821 11.821 0 0020.885 3.488"/>
              </svg>
              Enviar Confirmação via WhatsApp
            </h2>
            
            <div className="mb-4">
              <p className="text-gray-700 mb-2">
                <span className="font-medium">Para:</span> {selectedAppointment.client_name}
              </p>
              <p className="text-gray-700 mb-4">
                <span className="font-medium">Telefone:</span> {selectedAppointment.client_phone}
              </p>
            </div>
            
            <div className="mb-6">
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Mensagem (você pode editar):
              </label>
              <textarea
                value={whatsappMessage}
                onChange={(e) => setWhatsappMessage(e.target.value)}
                className="input min-h-[200px] text-sm"
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
                <svg className="h-4 w-4 mr-2" fill="currentColor" viewBox="0 0 24 24">
                  <path d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893A11.821 11.821 0 0020.885 3.488"/>
                </svg>
                Enviar WhatsApp
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;