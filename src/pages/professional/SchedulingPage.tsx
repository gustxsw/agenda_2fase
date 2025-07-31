import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { Calendar, Clock, Settings, CreditCard, CalendarDays, Plus, Edit, Trash2, Eye, User, MapPin } from 'lucide-react';
import { format, startOfWeek, endOfWeek, startOfMonth, endOfMonth, addDays, isSameDay, parseISO } from 'date-fns';
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
};

type SubscriptionStatus = {
  has_subscription: boolean;
  status: string;
  expires_at: string | null;
};

const SchedulingPage: React.FC = () => {
  const { user } = useAuth();
  const [currentDate, setCurrentDate] = useState(new Date());
  const [viewMode, setViewMode] = useState<'day' | 'week' | 'month'>('week');
  const [scheduleSettings, setScheduleSettings] = useState<ScheduleSettings | null>(null);
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [subscriptionStatus, setSubscriptionStatus] = useState<SubscriptionStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [showSettingsModal, setShowSettingsModal] = useState(false);
  const [isPaymentLoading, setIsPaymentLoading] = useState(false);

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
  }, []);

  useEffect(() => {
    if (subscriptionStatus?.status === 'active') {
      fetchAppointments();
    }
  }, [currentDate, viewMode, subscriptionStatus]);

  const fetchData = async () => {
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
      }

      // Fetch subscription status
      const subscriptionResponse = await fetch(`${apiUrl}/api/scheduling-subscription-status`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (subscriptionResponse.ok) {
        const subscription = await subscriptionResponse.json();
        setSubscriptionStatus(subscription);
      }

    } catch (error) {
      console.error('Error fetching data:', error);
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

      const response = await fetch(
        `${apiUrl}/api/appointments?start_date=${startDate}&end_date=${endDate}`,
        {
          headers: { 'Authorization': `Bearer ${token}` }
        }
      );

      if (response.ok) {
        const data = await response.json();
        setAppointments(data);
      }
    } catch (error) {
      console.error('Error fetching appointments:', error);
    }
  };

  const handleSubscriptionPayment = async () => {
    try {
      setIsPaymentLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/create-scheduling-subscription`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao criar pagamento');
      }

      const data = await response.json();
      window.open(data.init_point, '_blank');
    } catch (error) {
      console.error('Payment error:', error);
      setError(error instanceof Error ? error.message : 'Erro ao processar pagamento');
    } finally {
      setIsPaymentLoading(false);
    }
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL'
    }).format(value);
  };

  const formatTime = (time: string) => {
    return time.slice(0, 5); // Remove seconds
  };

  const getDayName = (dayNumber: number) => {
    const days = ['Domingo', 'Segunda', 'Terça', 'Quarta', 'Quinta', 'Sexta', 'Sábado'];
    return days[dayNumber];
  };

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
        <p className="text-gray-600">Carregando agenda...</p>
      </div>
    );
  }

  // Show subscription required screen
  if (!subscriptionStatus?.has_subscription || subscriptionStatus.status !== 'active') {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-8">
          <CalendarDays className="h-16 w-16 text-red-600 mx-auto mb-4" />
          <h1 className="text-3xl font-bold text-gray-900 mb-2">Sistema de Agendamentos</h1>
          <p className="text-gray-600">Gerencie sua agenda profissional de forma eficiente</p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-8">
          <div className="text-center mb-8">
            <h2 className="text-2xl font-semibold text-gray-900 mb-4">
              Assinatura Necessária
            </h2>
            <p className="text-gray-600 mb-6">
              Para acessar o sistema de agendamentos, você precisa de uma assinatura ativa.
            </p>
          </div>

          <div className="bg-red-50 rounded-lg p-6 mb-8">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-red-900 mb-2">
                  Sistema de Agendamentos Premium
                </h3>
                <ul className="text-red-700 space-y-1 text-sm">
                  <li>• Calendário completo (diário, semanal, mensal)</li>
                  <li>• Configuração de horários de trabalho</li>
                  <li>• Gestão de pacientes particulares</li>
                  <li>• Prontuários médicos completos</li>
                  <li>• Geração de documentos médicos</li>
                  <li>• Relatórios detalhados</li>
                </ul>
              </div>
              <div className="text-right">
                <div className="text-3xl font-bold text-red-600">R$ 49,90</div>
                <div className="text-sm text-red-500">por mês</div>
              </div>
            </div>
          </div>

          {error && (
            <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
              {error}
            </div>
          )}

          <div className="text-center">
            <button
              onClick={handleSubscriptionPayment}
              className={`btn btn-primary text-lg px-8 py-4 ${
                isPaymentLoading ? 'opacity-70 cursor-not-allowed' : ''
              }`}
              disabled={isPaymentLoading}
            >
              {isPaymentLoading ? (
                <>
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2 inline-block"></div>
                  Processando...
                </>
              ) : (
                <>
                  <CreditCard className="h-5 w-5 mr-2 inline" />
                  Assinar por R$ 49,90/mês
                </>
              )}
            </button>
            <p className="text-sm text-gray-500 mt-4">
              Pagamento seguro via Mercado Pago
            </p>
          </div>
        </div>
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
          
          <button className="btn btn-primary flex items-center">
            <Plus className="h-5 w-5 mr-2" />
            Novo Agendamento
          </button>
        </div>
      </div>

      {/* Subscription status */}
      {subscriptionStatus && (
        <div className="bg-green-50 border-l-4 border-green-400 p-4 mb-6">
          <div className="flex items-center">
            <CalendarDays className="h-5 w-5 text-green-600 mr-2" />
            <div>
              <p className="text-green-700 font-medium">
                Assinatura Ativa
              </p>
              <p className="text-green-600 text-sm">
                Válida até {subscriptionStatus.expires_at ? 
                  format(parseISO(subscriptionStatus.expires_at), "dd 'de' MMMM 'de' yyyy", { locale: ptBR }) : 
                  'N/A'
                }
              </p>
            </div>
          </div>
        </div>
      )}

      {/* View mode selector */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setViewMode('day')}
            className={`px-4 py-2 rounded-lg ${
              viewMode === 'day' 
                ? 'bg-red-600 text-white' 
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Dia
          </button>
          <button
            onClick={() => setViewMode('week')}
            className={`px-4 py-2 rounded-lg ${
              viewMode === 'week' 
                ? 'bg-red-600 text-white' 
                : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
            }`}
          >
            Semana
          </button>
          <button
            onClick={() => setViewMode('month')}
            className={`px-4 py-2 rounded-lg ${
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
            onClick={() => setCurrentDate(addDays(currentDate, -1))}
            className="p-2 hover:bg-gray-100 rounded-lg"
          >
            ←
          </button>
          <h2 className="text-lg font-semibold">
            {format(currentDate, "MMMM 'de' yyyy", { locale: ptBR })}
          </h2>
          <button
            onClick={() => setCurrentDate(addDays(currentDate, 1))}
            className="p-2 hover:bg-gray-100 rounded-lg"
          >
            →
          </button>
        </div>
      </div>

      {/* Calendar view */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
        {appointments.length === 0 ? (
          <div className="text-center py-12">
            <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              Nenhum agendamento encontrado
            </h3>
            <p className="text-gray-600">
              Não há agendamentos para o período selecionado.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {appointments.map((appointment) => (
              <div
                key={appointment.id}
                className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-4">
                    <div className="flex items-center text-gray-600">
                      <Calendar className="h-4 w-4 mr-1" />
                      {format(parseISO(appointment.appointment_date), "dd/MM/yyyy")}
                    </div>
                    <div className="flex items-center text-gray-600">
                      <Clock className="h-4 w-4 mr-1" />
                      {formatTime(appointment.appointment_time)}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <button className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg">
                      <Eye className="h-4 w-4" />
                    </button>
                    <button className="p-2 text-green-600 hover:bg-green-50 rounded-lg">
                      <Edit className="h-4 w-4" />
                    </button>
                    <button className="p-2 text-red-600 hover:bg-red-50 rounded-lg">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                
                <div className="mt-3">
                  <div className="flex items-center mb-2">
                    <User className="h-4 w-4 text-gray-500 mr-2" />
                    <span className="font-medium">{appointment.patient_name}</span>
                  </div>
                  
                  {appointment.service_name && (
                    <p className="text-sm text-gray-600 mb-1">
                      Serviço: {appointment.service_name}
                    </p>
                  )}
                  
                  {appointment.location_name && (
                    <div className="flex items-center text-sm text-gray-600 mb-1">
                      <MapPin className="h-3 w-3 mr-1" />
                      {appointment.location_name}
                    </div>
                  )}
                  
                  <p className="text-sm font-medium text-green-600">
                    {formatCurrency(appointment.value)}
                  </p>
                  
                  {appointment.notes && (
                    <p className="text-sm text-gray-500 mt-2">
                      {appointment.notes}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Settings Modal */}
      {showSettingsModal && scheduleSettings && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">Configurações da Agenda</h2>
            </div>
            
            <div className="p-6 space-y-6">
              <div>
                <h3 className="text-lg font-semibold mb-4">Dias de Trabalho</h3>
                <div className="grid grid-cols-7 gap-2">
                  {[0, 1, 2, 3, 4, 5, 6].map((day) => (
                    <label key={day} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={scheduleSettings.work_days.includes(day)}
                        className="mr-2"
                      />
                      <span className="text-sm">{getDayName(day)}</span>
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
                    value={scheduleSettings.work_start_time}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Fim do Expediente
                  </label>
                  <input
                    type="time"
                    value={scheduleSettings.work_end_time}
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
                    value={scheduleSettings.break_start_time}
                    className="input"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Fim do Intervalo
                  </label>
                  <input
                    type="time"
                    value={scheduleSettings.break_end_time}
                    className="input"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Duração da Consulta (minutos)
                </label>
                <input
                  type="number"
                  value={scheduleSettings.consultation_duration}
                  className="input"
                  min="15"
                  max="180"
                  step="15"
                />
              </div>
            </div>

            <div className="p-6 border-t border-gray-200 flex justify-end space-x-3">
              <button
                onClick={() => setShowSettingsModal(false)}
                className="btn btn-secondary"
              >
                Cancelar
              </button>
              <button className="btn btn-primary">
                Salvar Configurações
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SchedulingPage;