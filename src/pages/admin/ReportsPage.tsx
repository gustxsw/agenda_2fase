import React, { useState } from 'react';
import { BarChart2, Download, Calendar, MapPin, Users, Building } from 'lucide-react';

type RevenueReport = {
  total_revenue: number;
  revenue_by_professional: {
    professional_name: string;
    professional_percentage: number;
    revenue: number;
    consultation_count: number;
    professional_payment: number;
    clinic_revenue: number;
  }[];
  revenue_by_service: {
    service_name: string;
    revenue: number;
    consultation_count: number;
  }[];
};

type CityReport = {
  city: string;
  state: string;
  client_count: number;
  active_clients: number;
  pending_clients: number;
  expired_clients: number;
};

type ProfessionalCityReport = {
  city: string;
  state: string;
  total_professionals: number;
  categories: {
    category_name: string;
    count: number;
  }[];
};

const ReportsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'revenue' | 'clients' | 'professionals'>('revenue');
  const [startDate, setStartDate] = useState(getDefaultStartDate());
  const [endDate, setEndDate] = useState(getDefaultEndDate());
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<RevenueReport | null>(null);
  const [clientsReport, setClientsReport] = useState<CityReport[]>([]);
  const [professionalsReport, setProfessionalsReport] = useState<ProfessionalCityReport[]>([]);

  // Get API URL with fallback
  const getApiUrl = () => {
    if (import.meta.env.VITE_API_URL) {
      return import.meta.env.VITE_API_URL;
    }
    
    if (window.location.hostname === 'cartaoquiroferreira.com.br' || 
        window.location.hostname === 'www.cartaoquiroferreira.com.br') {
      return 'https://convenioquiroferreira.onrender.com';
    }
    
    return 'http://localhost:3001';
  };
  
  // Get default date range (current month)
  function getDefaultStartDate() {
    const date = new Date();
    date.setDate(1); // First day of current month
    return date.toISOString().split('T')[0];
  }
  
  function getDefaultEndDate() {
    const date = new Date();
    return date.toISOString().split('T')[0];
  }
  
  const fetchReport = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      console.log('Fetching report from:', apiUrl);
      
      const response = await fetch(
        `${apiUrl}/api/reports/revenue?start_date=${startDate}&end_date=${endDate}`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );
      
      if (!response.ok) {
        throw new Error('Falha ao carregar relatório');
      }
      
      const data = await response.json();
      setReport(data);
    } catch (error) {
      console.error('Error fetching report:', error);
      setError('Não foi possível carregar o relatório');
      setReport(null);
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchReport();
  };
  
  const fetchCityReports = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      // Fetch clients by city
      const clientsResponse = await fetch(`${apiUrl}/api/reports/clients-by-city`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (clientsResponse.ok) {
        const clientsData = await clientsResponse.json();
        setClientsReport(clientsData);
      }
      
      // Fetch professionals by city
      const professionalsResponse = await fetch(`${apiUrl}/api/reports/professionals-by-city`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (professionalsResponse.ok) {
        const professionalsData = await professionalsResponse.json();
        setProfessionalsReport(professionalsData);
      }
    } catch (error) {
      console.error('Error fetching city reports:', error);
      setError('Não foi possível carregar os relatórios por cidade');
    } finally {
      setIsLoading(false);
    }
  };
  
  const handleTabChange = (tab: 'revenue' | 'clients' | 'professionals') => {
    setActiveTab(tab);
    if (tab === 'clients' || tab === 'professionals') {
      fetchCityReports();
    }
  };
  
  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };
  
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
  };
  
  const calculateTotalClinicRevenue = () => {
    if (!report) return 0;
    return report.revenue_by_professional.reduce((total, prof) => total + prof.clinic_revenue, 0);
  };
  
  const calculateTotalProfessionalPayments = () => {
    if (!report) return 0;
    return report.revenue_by_professional.reduce((total, prof) => total + prof.professional_payment, 0);
  };
  
  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Relatórios</h1>
        <p className="text-gray-600">Visualize dados de faturamento e distribuição geográfica</p>
      </div>
      
      {/* Tab Navigation */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 mb-6">
        <div className="flex border-b border-gray-200">
          <button
            onClick={() => handleTabChange('revenue')}
            className={`px-6 py-4 font-medium text-sm border-b-2 transition-colors ${
              activeTab === 'revenue'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <BarChart2 className="h-5 w-5 inline mr-2" />
            Relatório Financeiro
          </button>
          <button
            onClick={() => handleTabChange('clients')}
            className={`px-6 py-4 font-medium text-sm border-b-2 transition-colors ${
              activeTab === 'clients'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <Users className="h-5 w-5 inline mr-2" />
            Clientes por Cidade
          </button>
          <button
            onClick={() => handleTabChange('professionals')}
            className={`px-6 py-4 font-medium text-sm border-b-2 transition-colors ${
              activeTab === 'professionals'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <Building className="h-5 w-5 inline mr-2" />
            Profissionais por Cidade
          </button>
        </div>
      </div>
      
      {/* Revenue Report Tab */}
      {activeTab === 'revenue' && (
        <>
      <div className="card mb-6">
        <div className="flex items-center mb-4">
          <Calendar className="h-6 w-6 text-red-600 mr-2" />
          <h2 className="text-xl font-semibold">Selecione o Período</h2>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label htmlFor="startDate" className="block text-sm font-medium text-gray-700 mb-1">
                Data Inicial
              </label>
              <input
                id="startDate"
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="input"
                required
              />
            </div>
            
            <div>
              <label htmlFor="endDate" className="block text-sm font-medium text-gray-700 mb-1">
                Data Final
              </label>
              <input
                id="endDate"
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="input"
                required
              />
            </div>
            
            <div className="flex items-end">
              <button
                type="submit"
                className={`btn btn-primary w-full ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
                disabled={isLoading}
              >
                {isLoading ? 'Carregando...' : 'Gerar Relatório'}
              </button>
            </div>
          </div>
        </form>
      </div>
      
      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-md mb-6">
          {error}
        </div>
      )}
      
      {report && (
        <div className="space-y-6">
          <div className="card">
            <div className="flex justify-between items-center mb-4">
              <div className="flex items-center">
                <BarChart2 className="h-6 w-6 text-red-600 mr-2" />
                <h2 className="text-xl font-semibold">Resumo do Período</h2>
              </div>
              
              <button className="btn btn-outline flex items-center">
                <Download className="h-5 w-5 mr-2" />
                Exportar
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="p-4 bg-red-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Faturamento Total</p>
                  <p className="text-3xl font-bold text-red-600">
                    {formatCurrency(report.total_revenue)}
                  </p>
                </div>
              </div>
              
              <div className="p-4 bg-green-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Receita do Convênio</p>
                  <p className="text-3xl font-bold text-green-600">
                    {formatCurrency(calculateTotalClinicRevenue())}
                  </p>
                </div>
              </div>
              
              <div className="p-4 bg-blue-50 rounded-lg">
                <div className="text-center">
                  <p className="text-gray-600 mb-1">Faturamento dos Profissionais</p>
                  <p className="text-3xl font-bold text-blue-600">
                    {formatCurrency(calculateTotalProfessionalPayments())}
                  </p>
                </div>
              </div>
            </div>
            
            <p className="text-sm text-gray-600 text-center">
              Período: {formatDate(startDate)} a {formatDate(endDate)}
            </p>
          </div>
          
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">Faturamento por Profissional</h3>
            
            {report.revenue_by_professional.length === 0 ? (
              <div className="text-center py-4 bg-gray-50 rounded-lg">
                <p className="text-gray-600">Nenhum dado disponível para o período.</p>
              </div>
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Profissional</th>
                      <th>Porcentagem</th>
                      <th>Consultas</th>
                      <th>Faturamento</th>
                      <th>Valor a Pagar</th>
                      <th>Valor a Receber</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.revenue_by_professional.map((item, index) => (
                      <tr key={index}>
                        <td>{item.professional_name}</td>
                        <td>{item.professional_percentage}%</td>
                        <td>{item.consultation_count}</td>
                        <td>{formatCurrency(item.revenue)}</td>
                        <td>{formatCurrency(item.professional_payment)}</td>
                        <td>{formatCurrency(item.clinic_revenue)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          
          <div className="card">
            <h3 className="text-lg font-semibold mb-4">Faturamento por Serviço</h3>
            
            {report.revenue_by_service.length === 0 ? (
              <div className="text-center py-4 bg-gray-50 rounded-lg">
                <p className="text-gray-600">Nenhum dado disponível para o período.</p>
              </div>
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Serviço</th>
                      <th>Consultas</th>
                      <th>Faturamento</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.revenue_by_service.map((item, index) => (
                      <tr key={index}>
                        <td>{item.service_name}</td>
                        <td>{item.consultation_count}</td>
                        <td>{formatCurrency(item.revenue)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
        </>
      )}
      
      {/* Clients by City Tab */}
      {activeTab === 'clients' && (
        <div className="card">
          <div className="flex justify-between items-center mb-6">
            <div className="flex items-center">
              <MapPin className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Clientes por Cidade</h2>
            </div>
            
            <button 
              onClick={fetchCityReports}
              className={`btn btn-primary ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
              disabled={isLoading}
            >
              {isLoading ? 'Carregando...' : 'Atualizar'}
            </button>
          </div>
          
          {error && (
            <div className="bg-red-50 text-red-600 p-4 rounded-md mb-6">
              {error}
            </div>
          )}
          
          {isLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Carregando relatório...</p>
            </div>
          ) : clientsReport.length === 0 ? (
            <div className="text-center py-8 bg-gray-50 rounded-lg">
              <MapPin className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Nenhum dado disponível
              </h3>
              <p className="text-gray-600">
                Não há clientes cadastrados com informações de cidade.
              </p>
            </div>
          ) : (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-blue-600 font-medium">Total de Cidades</p>
                    <p className="text-2xl font-bold text-blue-700">
                      {clientsReport.length}
                    </p>
                  </div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-green-600 font-medium">Clientes Ativos</p>
                    <p className="text-2xl font-bold text-green-700">
                      {clientsReport.reduce((sum, city) => sum + city.active_clients, 0)}
                    </p>
                  </div>
                </div>
                <div className="bg-yellow-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-yellow-600 font-medium">Clientes Pendentes</p>
                    <p className="text-2xl font-bold text-yellow-700">
                      {clientsReport.reduce((sum, city) => sum + city.pending_clients, 0)}
                    </p>
                  </div>
                </div>
                <div className="bg-red-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-red-600 font-medium">Clientes Vencidos</p>
                    <p className="text-2xl font-bold text-red-700">
                      {clientsReport.reduce((sum, city) => sum + city.expired_clients, 0)}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Cidade</th>
                      <th>Estado</th>
                      <th>Total de Clientes</th>
                      <th>Ativos</th>
                      <th>Pendentes</th>
                      <th>Vencidos</th>
                    </tr>
                  </thead>
                  <tbody>
                    {clientsReport.map((city, index) => (
                      <tr key={index}>
                        <td className="flex items-center">
                          <MapPin className="h-4 w-4 text-gray-500 mr-2" />
                          {city.city}
                        </td>
                        <td>{city.state}</td>
                        <td className="font-medium">{city.client_count}</td>
                        <td>
                          <span className="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs font-medium">
                            {city.active_clients}
                          </span>
                        </td>
                        <td>
                          <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded-full text-xs font-medium">
                            {city.pending_clients}
                          </span>
                        </td>
                        <td>
                          <span className="px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-medium">
                            {city.expired_clients}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}
      
      {/* Professionals by City Tab */}
      {activeTab === 'professionals' && (
        <div className="card">
          <div className="flex justify-between items-center mb-6">
            <div className="flex items-center">
              <Building className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Profissionais por Cidade</h2>
            </div>
            
            <button 
              onClick={fetchCityReports}
              className={`btn btn-primary ${isLoading ? 'opacity-70 cursor-not-allowed' : ''}`}
              disabled={isLoading}
            >
              {isLoading ? 'Carregando...' : 'Atualizar'}
            </button>
          </div>
          
          {error && (
            <div className="bg-red-50 text-red-600 p-4 rounded-md mb-6">
              {error}
            </div>
          )}
          
          {isLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Carregando relatório...</p>
            </div>
          ) : professionalsReport.length === 0 ? (
            <div className="text-center py-8 bg-gray-50 rounded-lg">
              <Building className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Nenhum dado disponível
              </h3>
              <p className="text-gray-600">
                Não há profissionais cadastrados com informações de cidade.
              </p>
            </div>
          ) : (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-blue-600 font-medium">Total de Cidades</p>
                    <p className="text-2xl font-bold text-blue-700">
                      {professionalsReport.length}
                    </p>
                  </div>
                </div>
                <div className="bg-green-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-green-600 font-medium">Total de Profissionais</p>
                    <p className="text-2xl font-bold text-green-700">
                      {professionalsReport.reduce((sum, city) => sum + city.total_professionals, 0)}
                    </p>
                  </div>
                </div>
                <div className="bg-purple-50 p-4 rounded-lg">
                  <div className="text-center">
                    <p className="text-purple-600 font-medium">Categorias Ativas</p>
                    <p className="text-2xl font-bold text-purple-700">
                      {[...new Set(professionalsReport.flatMap(city => city.categories.map(cat => cat.category_name)))].length}
                    </p>
                  </div>
                </div>
              </div>
              
              <div className="space-y-6">
                {professionalsReport.map((city, index) => (
                  <div key={index} className="bg-gray-50 rounded-lg p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center">
                        <MapPin className="h-5 w-5 text-red-600 mr-2" />
                        <h3 className="text-lg font-semibold text-gray-900">
                          {city.city}, {city.state}
                        </h3>
                      </div>
                      <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-medium">
                        {city.total_professionals} profissionais
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {city.categories.map((category, catIndex) => (
                        <div key={catIndex} className="bg-white p-4 rounded-lg border border-gray-200">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium text-gray-700">
                              {category.category_name || 'Sem categoria'}
                            </span>
                            <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded-full text-xs font-medium">
                              {category.count}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default ReportsPage;