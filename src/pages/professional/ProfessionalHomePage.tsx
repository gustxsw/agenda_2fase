import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { Link } from 'react-router-dom';
import { format } from 'date-fns';
import { ptBR } from 'date-fns/locale';
import { CalendarClock, PlusCircle, DollarSign, TrendingUp, Users, AlertCircle, RefreshCw, Camera, Upload } from 'lucide-react';
import PaymentSection from './PaymentSection';

type RevenueReport = {
  summary: {
    professional_percentage: number;
    total_revenue: number;
    consultation_count: number;
    amount_to_pay: number;
  };
  consultations: {
    date: string;
    client_name: string;
    service_name: string;
    total_value: number;
    amount_to_pay: number;
  }[];
};

const ProfessionalHomePage: React.FC = () => {
  const { user } = useAuth();
  const [revenueReport, setRevenueReport] = useState<RevenueReport | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [photoUrl, setPhotoUrl] = useState<string | null>(null);
  const [isUploadingPhoto, setIsUploadingPhoto] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [uploadSuccess, setUploadSuccess] = useState('');

  // Get API URL with fallback
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }

    return "http://localhost:3001";
  };
  
  const getDefaultDateRange = () => {
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    return {
      start: firstDay.toISOString().split('T')[0],
      end: lastDay.toISOString().split('T')[0],
    };
  };
  
  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      const dateRange = getDefaultDateRange();
      
      console.log('🔄 Fetching professional data from:', apiUrl);
      console.log('🔄 Date range:', dateRange);
      console.log('🔄 User ID:', user?.id);
      
      // Fetch user data to get photo_url
      const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setPhotoUrl(userData.photo_url);
      }
      
      // 🔥 LIBERADO: Sempre buscar dados de receita
      const revenueResponse = await fetch(
        `${apiUrl}/api/reports/professional-revenue?start_date=${dateRange.start}&end_date=${dateRange.end}`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );
      
      console.log('📡 Revenue response status:', revenueResponse.status);
      
      if (!revenueResponse.ok) {
        const errorData = await revenueResponse.json();
        console.error('❌ Revenue response error:', errorData);
        throw new Error(errorData.message || 'Falha ao carregar relatório financeiro');
      }
      
      const revenueData = await revenueResponse.json();
      console.log('✅ Revenue data received:', revenueData);
      setRevenueReport(revenueData);
    } catch (error) {
      console.error('❌ Error fetching data:', error);
      setError(error instanceof Error ? error.message : 'Não foi possível carregar os dados. Verifique sua conexão e tente novamente.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePhotoUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith('image/')) {
      setUploadError('Por favor, selecione apenas arquivos de imagem');
      return;
    }

    // Validate file size (5MB)
    if (file.size > 5 * 1024 * 1024) {
      setUploadError('A imagem deve ter no máximo 5MB');
      return;
    }

    try {
      setIsUploadingPhoto(true);
      setUploadError('');
      setUploadSuccess('');

      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const formData = new FormData();
      formData.append('image', file);

      const response = await fetch(`${apiUrl}/api/upload-image`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao fazer upload da imagem');
      }

      const data = await response.json();
      setPhotoUrl(data.imageUrl);
      setUploadSuccess('Imagem atualizada com sucesso!');

      // Clear success message after 3 seconds
      setTimeout(() => {
        setUploadSuccess('');
      }, 3000);

    } catch (error) {
      console.error('Error uploading photo:', error);
      setUploadError(error instanceof Error ? error.message : 'Erro ao fazer upload da imagem');
    } finally {
      setIsUploadingPhoto(false);
    }
  };
  
  useEffect(() => {
    if (user?.id) {
      fetchData();
    }
  }, [user?.id]);
  
  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString);
      return format(date, "dd 'de' MMMM 'de' yyyy 'às' HH:mm", { locale: ptBR });
    } catch (error) {
      console.error('Error formatting date:', error);
      return dateString;
    }
  };
  
  const formatCurrency = (value: number | string) => {
    const numericValue = typeof value === 'string' ? parseFloat(value) : value;
    if (isNaN(numericValue)) return 'R$ 0,00';
    
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(numericValue);
  };
  
  const handleRetry = () => {
    fetchData();
  };
  
  return (
    <div>
      <div className="flex justify-between items-start mb-6">
        <div className="flex items-center space-x-4">
          {/* Professional Photo */}
          <div className="relative">
            <div className="w-16 h-16 rounded-full overflow-hidden border-2 border-red-100">
              {photoUrl ? (
                <img
                  src={photoUrl}
                  alt={`Foto de ${user?.name}`}
                  className="w-full h-full object-cover"
                  onError={(e) => {
                    const target = e.target as HTMLImageElement;
                    target.style.display = 'none';
                    target.nextElementSibling?.classList.remove('hidden');
                  }}
                />
              ) : null}
              <div className={`w-full h-full bg-red-100 flex items-center justify-center ${photoUrl ? 'hidden' : ''}`}>
                <Camera className="h-6 w-6 text-red-600" />
              </div>
            </div>
            
            {/* Upload button */}
            <label className="absolute -bottom-1 -right-1 bg-red-600 text-white rounded-full p-1.5 cursor-pointer hover:bg-red-700 transition-colors shadow-sm">
              <Upload className="h-3 w-3" />
              <input
                type="file"
                accept="image/*"
                onChange={handlePhotoUpload}
                className="hidden"
                disabled={isUploadingPhoto}
              />
            </label>
            
            {isUploadingPhoto && (
              <div className="absolute inset-0 bg-black bg-opacity-50 rounded-full flex items-center justify-center">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              </div>
            )}
          </div>

          <div>
            <h1 className="text-2xl font-bold text-gray-900">Olá, {user?.name}</h1>
            <p className="text-gray-600">Bem-vindo ao seu painel de profissional.</p>
          </div>
        </div>
        
        <div className="flex space-x-3">
          {error && (
            <button
              onClick={handleRetry}
              className="btn btn-outline flex items-center"
              disabled={isLoading}
            >
              <RefreshCw className={`h-5 w-5 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Tentar Novamente
            </button>
          )}
          
          <Link to="/professional/register-consultation" className="btn btn-primary flex items-center">
            <PlusCircle className="h-5 w-5 mr-2" />
            Nova Consulta
          </Link>
        </div>
      </div>

      {/* Upload feedback messages */}
      {uploadError && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
            <p className="text-red-700">{uploadError}</p>
          </div>
        </div>
      )}

      {uploadSuccess && (
        <div className="bg-green-50 border-l-4 border-green-600 p-4 mb-6">
          <div className="flex items-center">
            <Camera className="h-5 w-5 text-green-600 mr-2" />
            <p className="text-green-700">{uploadSuccess}</p>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
            <div>
              <p className="text-red-700 font-medium">Erro ao carregar dados</p>
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando dados...</p>
        </div>
      ) : revenueReport ? (
        <>
          {/* Statistics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">Consultas Realizadas</h3>
                <Users className="h-5 w-5 text-blue-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {revenueReport.summary.consultation_count || 0}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Atendimentos realizados
              </p>
            </div>
            
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">Faturamento Total</h3>
                <TrendingUp className="h-5 w-5 text-green-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency(revenueReport.summary.total_revenue || 0)}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                {revenueReport.summary.professional_percentage || 50}% é sua porcentagem
              </p>
            </div>
            
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">Contas a Pagar</h3>
                <DollarSign className="h-5 w-5 text-red-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency(revenueReport.summary.amount_to_pay || 0)}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Valor a ser repassado ao convênio
              </p>
            </div>
          </div>

          {/* Payment Section */}
          {revenueReport.summary.amount_to_pay > 0 && (
            <PaymentSection amount={revenueReport.summary.amount_to_pay} />
          )}

          {/* Consultations Table */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-center mb-6">
              <CalendarClock className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Consultas Realizadas</h2>
            </div>
            
            {!revenueReport.consultations || revenueReport.consultations.length === 0 ? (
              <div className="text-center py-12 bg-gray-50 rounded-lg">
                <CalendarClock className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Nenhuma consulta registrada
                </h3>
                <p className="text-gray-600 mb-4">
                  Você ainda não registrou nenhuma consulta este mês.
                </p>
                <Link to="/professional/register-consultation" className="btn btn-primary inline-flex items-center">
                  <PlusCircle className="h-5 w-5 mr-2" />
                  Registrar Primeira Consulta
                </Link>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead>
                    <tr className="border-b border-gray-200">
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Data</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Cliente</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Serviço</th>
                      <th className="text-right py-3 px-4 font-medium text-gray-700">Valor Total</th>
                      <th className="text-right py-3 px-4 font-medium text-gray-700">Valor a Pagar</th>
                    </tr>
                  </thead>
                  <tbody>
                    {revenueReport.consultations.map((consultation, index) => (
                      <tr key={index} className="border-b border-gray-100 hover:bg-gray-50">
                        <td className="py-3 px-4 text-sm text-gray-600">
                          {formatDate(consultation.date)}
                        </td>
                        <td className="py-3 px-4 text-sm text-gray-900">
                          {consultation.client_name || 'N/A'}
                        </td>
                        <td className="py-3 px-4 text-sm text-gray-600">
                          {consultation.service_name || 'N/A'}
                        </td>
                        <td className="py-3 px-4 text-sm text-gray-900 text-right font-medium">
                          {formatCurrency(consultation.total_value)}
                        </td>
                        <td className="py-3 px-4 text-sm text-red-600 text-right font-medium">
                          {formatCurrency(consultation.amount_to_pay)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      ) : (
        <div className="text-center py-12 bg-gray-50 rounded-lg">
          <AlertCircle className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            Dados não disponíveis
          </h3>
          <p className="text-gray-600 mb-4">
            Não foi possível carregar os dados do relatório.
          </p>
          <button 
            onClick={handleRetry} 
            className="btn btn-primary"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <RefreshCw className="h-5 w-5 mr-2 animate-spin" />
                Carregando...
              </>
            ) : (
              <>
                <RefreshCw className="h-5 w-5 mr-2" />
                Tentar Novamente
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};

export default ProfessionalHomePage;