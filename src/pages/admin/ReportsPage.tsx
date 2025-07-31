import React, { useState } from 'react';
import { BarChart2, Download, Calendar } from 'lucide-react';

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

const ReportsPage: React.FC = () => {
  const [startDate, setStartDate] = useState(getDefaultStartDate());
  const [endDate, setEndDate] = useState(getDefaultEndDate());
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [report, setReport] = useState<RevenueReport | null>(null);

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
        <h1 className="text-2xl font-bold text-gray-900">Relatórios Financeiros</h1>
        <p className="text-gray-600">Visualize dados de faturamento por período</p>
      </div>
      
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
    </div>
  );
};

export default ReportsPage;