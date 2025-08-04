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
  is_admin_granted?: boolean;
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

  // Settings form state
  const [settingsForm, setSettingsForm] = useState({
    work_days: [1, 2, 3, 4, 5],
    work_start_time: '08:00',
    work_end_time: '18:00',
    break_start_time: '12:00',
    break_end_time: '13:00',
    consultation_duration: 60
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
  }, []);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // MVP: Simulate subscription check
      // In production, this would check both paid subscription and admin-granted access
      const mockSubscription = {
        has_subscription: true,
        status: 'active',
        expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(), // 90 days from now
        is_admin_granted: true // MVP: Assume admin granted access
      };

      setSubscriptionStatus(mockSubscription);

      // Mock schedule settings
      const mockSettings = {
        professional_id: user?.id || 0,
        work_days: [1, 2, 3, 4, 5],
        work_start_time: '08:00',
        work_end_time: '18:00',
        break_start_time: '12:00',
        break_end_time: '13:00',
        consultation_duration: 60,
        has_scheduling_subscription: true
      };

      setScheduleSettings(mockSettings);
      setSettingsForm({
        work_days: mockSettings.work_days,
        work_start_time: mockSettings.work_start_time,
        work_end_time: mockSettings.work_end_time,
        break_start_time: mockSettings.break_start_time,
        break_end_time: mockSettings.break_end_time,
        consultation_duration: mockSettings.consultation_duration
      });

      // Mock appointments
      setAppointments([]);

    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Erro ao carregar dados');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSubscriptionPayment = async () => {
    try {
      setIsPaymentLoading(true);
      setError('');

      // MVP: Simulate payment process
      setTimeout(() => {
        setSubscriptionStatus({
          has_subscription: true,
          status: 'active',
          expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
          is_admin_granted: false
        });
        setIsPaymentLoading(false);
      }, 2000);
    } catch (error) {
      console.error('Payment error:', error);
      setError('Erro ao processar pagamento');
      setIsPaymentLoading(false);
    }
  };

  const handleSettingsSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      // MVP: Just update local state
      setScheduleSettings(prev => prev ? {
        ...prev,
        ...settingsForm
      } : null);
      
      setShowSettingsModal(false);
    } catch (error) {
      console.error('Error saving settings:', error);
      setError('Erro ao salvar configurações');
    }
  };

  const formatTime = (time: string) => {
    return time.slice(0, 5); // Remove seconds
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

  if (isLoading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
        <p className="text-gray-600">Carregando agenda...</p>
      </div>
    );
  }

  // Show subscription required screen
  if (!subscriptionStatus || !subscriptionStatus.has_subscription || subscriptionStatus.status !== 'active') {
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
        <div className={`border-l-4 p-4 mb-6 ${
          subscriptionStatus.is_admin_granted 
            ? 'bg-blue-50 border-blue-400' 
            : 'bg-green-50 border-green-400'
        }`}>
          <div className="flex items-center">
            <CalendarDays className={`h-5 w-5 mr-2 ${
              subscriptionStatus.is_admin_granted ? 'text-blue-600' : 'text-green-600'
            }`} />
            <div>
              <p className={`font-medium ${
                subscriptionStatus.is_admin_granted ? 'text-blue-700' : 'text-green-700'
              }`}>
                {subscriptionStatus.is_admin_granted ? 'Acesso Concedido pelo Convênio' : 'Assinatura Ativa'}
              </p>
              <p className={`text-sm ${
                subscriptionStatus.is_admin_granted ? 'text-blue-600' : 'text-green-600'
              }`}>
                Válida até {subscriptionStatus.expires_at ? 
                  format(parseISO(subscriptionStatus.expires_at), "dd 'de' MMMM 'de' yyyy", { locale: ptBR }) : 
                  'N/A'
                }
              </p>
              {subscriptionStatus.is_admin_granted && (
                <p className="text-xs text-blue-500 mt-1">
                  🎁 Acesso gratuito concedido pela administração
                </p>
              )}
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
        <div className="text-center py-12">
          <Calendar className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            Sistema de Agenda Ativo
          </h3>
          <p className="text-gray-600">
            Sua agenda está configurada e pronta para uso. Os agendamentos aparecerão aqui.
          </p>
        </div>
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
                    <label key={day} className="flex items-center">
                      <input
                        type="checkbox"
                        checked={settingsForm.work_days.includes(day)}
                        onChange={(e) => handleWorkDayChange(day, e.target.checked)}
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
                <input
                  type="number"
                  value={settingsForm.consultation_duration}
                  onChange={(e) => setSettingsForm(prev => ({ ...prev, consultation_duration: parseInt(e.target.value) }))}
                  className="input"
                  min="15"
                  max="180"
                  step="15"
                />
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
    </div>
  );
};

export default SchedulingPage;