import React, { useState, useEffect } from 'react';
import { Calendar, Clock, User, Plus, Edit, Check, X, AlertCircle, ChevronLeft, ChevronRight } from 'lucide-react';
import { format, addDays, subDays, startOfDay, isSameDay } from 'date-fns';
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
};

type NewAppointment = {
  client_cpf: string;
  date: string;
  time: string;
  service_id: number;
  notes: string;
};

type Service = {
  id: number;
  name: string;
  base_price: number;
};

const SchedulingPage: React.FC = () => {
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal states
  const [showNewAppointmentModal, setShowNewAppointmentModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [selectedAppointment, setSelectedAppointment] = useState<Appointment | null>(null);
  
  // Form state
  const [newAppointment, setNewAppointment] = useState<NewAppointment>({
    client_cpf: '',
    date: format(new Date(), 'yyyy-MM-dd'),
    time: '',
    service_id: 0,
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

  useEffect(() => {
    fetchServices();
  }, []);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      const dateStr = format(selectedDate, 'yyyy-MM-dd');
      
      const response = await fetch(`${apiUrl}/api/appointments?date=${dateStr}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (!response.ok) {
        throw new Error('Falha ao carregar agendamentos');
      }
      
      const data = await response.json();
      setAppointments(data);
    } catch (error) {
      console.error('Error fetching appointments:', error);
      setError('Não foi possível carregar os agendamentos');
    } finally {
      setIsLoading(false);
    }
  };

  const fetchServices = async () => {
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/services`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (response.ok) {
        const data = await response.json();
        setServices(data);
      }
    } catch (error) {
      console.error('Error fetching services:', error);
    }
  };

  const updateAppointmentStatus = async (appointmentId: number, newStatus: string) => {
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/appointments/${appointmentId}/status`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status: newStatus })
      });
      
      if (!response.ok) {
        throw new Error('Falha ao atualizar status');
      }
      
      await fetchData();
      setSuccess('Status atualizado com sucesso!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError('Erro ao atualizar status');
      setTimeout(() => setError(''), 3000);
    }
  };

  const createAppointment = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      // First, search for client by CPF
      const clientResponse = await fetch(`${apiUrl}/api/clients/lookup?cpf=${newAppointment.client_cpf.replace(/\D/g, '')}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (!clientResponse.ok) {
        throw new Error('Cliente não encontrado');
      }
      
      const clientData = await clientResponse.json();
      
      if (clientData.subscription_status !== 'active') {
        throw new Error('Cliente não possui assinatura ativa');
      }
      
      // Create appointment
      const appointmentResponse = await fetch(`${apiUrl}/api/appointments`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          client_id: clientData.id,
          service_id: newAppointment.service_id,
          date: newAppointment.date,
          time: newAppointment.time,
          notes: newAppointment.notes
        })
      });
      
      if (!appointmentResponse.ok) {
        const errorData = await appointmentResponse.json();
        throw new Error(errorData.message || 'Falha ao criar agendamento');
      }
      
      await fetchData();
      setShowNewAppointmentModal(false);
      setNewAppointment({
        client_cpf: '',
        date: format(selectedDate, 'yyyy-MM-dd'),
        time: '',
        service_id: 0,
        notes: ''
      });
      setSuccess('Agendamento criado com sucesso!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao criar agendamento');
    }
  };

  const deleteAppointment = async (appointmentId: number) => {
    if (!confirm('Tem certeza que deseja excluir este agendamento?')) return;
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/appointments/${appointmentId}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      
      if (!response.ok) {
        throw new Error('Falha ao excluir agendamento');
      }
      
      await fetchData();
      setSuccess('Agendamento excluído com sucesso!');
      setTimeout(() => setSuccess(''), 3000);
    } catch (error) {
      setError('Erro ao excluir agendamento');
      setTimeout(() => setError(''), 3000);
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

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    return limitedValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
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
  const dailyAppointments = appointments.filter(apt => 
    isSameDay(new Date(apt.date), selectedDate)
  ).sort((a, b) => a.time.localeCompare(b.time));

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Agenda</h1>
          <p className="text-gray-600">Gerencie seus agendamentos diários</p>
        </div>
        
        <button
          onClick={() => setShowNewAppointmentModal(true)}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Novo Agendamento
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
              {format(selectedDate, "EEEE, dd 'de' MMMM 'de' yyyy", { locale: ptBR })}
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
              Que tal criar um novo agendamento?
            </p>
            <button
              onClick={() => setShowNewAppointmentModal(true)}
              className="btn btn-primary inline-flex items-center"
            >
              <Plus className="h-5 w-5 mr-2" />
              Novo Agendamento
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
                      <div className="text-center">
                        <div className="text-lg font-bold text-gray-900">
                          {appointment.time}
                        </div>
                        <Clock className="h-4 w-4 text-gray-400 mx-auto" />
                      </div>
                      
                      <div className="flex-1">
                        <div className="flex items-center mb-1">
                          <User className="h-4 w-4 text-gray-400 mr-2" />
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
                          <p className="text-sm text-gray-500 mt-1">
                            {appointment.notes}
                          </p>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-medium ${statusInfo.className}`}>
                        {statusInfo.text}
                      </span>
                      
                      <div className="flex items-center space-x-1">
                        {appointment.status === 'scheduled' && (
                          <button
                            onClick={() => updateAppointmentStatus(appointment.id, 'confirmed')}
                            className="p-2 text-green-600 hover:bg-green-50 rounded-lg"
                            title="Confirmar"
                          >
                            <Check className="h-4 w-4" />
                          </button>
                        )}
                        
                        {(appointment.status === 'scheduled' || appointment.status === 'confirmed') && (
                          <button
                            onClick={() => updateAppointmentStatus(appointment.id, 'completed')}
                            className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg"
                            title="Marcar como concluído"
                          >
                            <Check className="h-4 w-4" />
                          </button>
                        )}
                        
                        {appointment.status !== 'cancelled' && appointment.status !== 'completed' && (
                          <button
                            onClick={() => updateAppointmentStatus(appointment.id, 'cancelled')}
                            className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
                            title="Cancelar"
                          >
                            <X className="h-4 w-4" />
                          </button>
                        )}
                        
                        <button
                          onClick={() => deleteAppointment(appointment.id)}
                          className="p-2 text-gray-600 hover:bg-gray-50 rounded-lg"
                          title="Excluir"
                        >
                          <X className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Statistics */}
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

      {/* New Appointment Modal */}
      {showNewAppointmentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">Novo Agendamento</h2>
            </div>

            <form onSubmit={createAppointment} className="p-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    CPF do Cliente *
                  </label>
                  <input
                    type="text"
                    value={formatCpf(newAppointment.client_cpf)}
                    onChange={(e) => setNewAppointment(prev => ({ 
                      ...prev, 
                      client_cpf: e.target.value.replace(/\D/g, '') 
                    }))}
                    className="input"
                    placeholder="000.000.000-00"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data *
                  </label>
                  <input
                    type="date"
                    value={newAppointment.date}
                    onChange={(e) => setNewAppointment(prev => ({ ...prev, date: e.target.value }))}
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Horário *
                  </label>
                  <select
                    value={newAppointment.time}
                    onChange={(e) => setNewAppointment(prev => ({ ...prev, time: e.target.value }))}
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
                    value={newAppointment.service_id}
                    onChange={(e) => setNewAppointment(prev => ({ ...prev, service_id: Number(e.target.value) }))}
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
                    Observações
                  </label>
                  <textarea
                    value={newAppointment.notes}
                    onChange={(e) => setNewAppointment(prev => ({ ...prev, notes: e.target.value }))}
                    className="input min-h-[80px]"
                    placeholder="Observações sobre o agendamento..."
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={() => setShowNewAppointmentModal(false)}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  Criar Agendamento
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;