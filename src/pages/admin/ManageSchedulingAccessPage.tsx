import React, { useState, useEffect } from 'react';
import { Calendar, UserCheck, Plus, Edit, Trash2, Search, Filter, Clock, Gift, AlertCircle, X, Check } from 'lucide-react';

type Professional = {
  id: number;
  name: string;
  email: string;
  phone: string;
  category_name: string;
  has_scheduling_access: boolean;
  access_expires_at: string | null;
  access_granted_by: string | null;
  access_granted_at: string | null;
};

const ManageSchedulingAccessPage: React.FC = () => {
  const [professionals, setProfessionals] = useState<Professional[]>([]);
  const [filteredProfessionals, setFilteredProfessionals] = useState<Professional[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'grant' | 'extend'>('grant');
  const [selectedProfessional, setSelectedProfessional] = useState<Professional | null>(null);
  
  // Form state
  const [expiryDate, setExpiryDate] = useState('');
  const [reason, setReason] = useState('');
  
  // Delete confirmation state
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);
  const [professionalToRevoke, setProfessionalToRevoke] = useState<Professional | null>(null);

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
    let filtered = professionals;

    if (searchTerm) {
      filtered = filtered.filter(prof =>
        prof.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        prof.email?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (filterStatus) {
      if (filterStatus === 'with_access') {
        filtered = filtered.filter(prof => prof.has_scheduling_access);
      } else if (filterStatus === 'without_access') {
        filtered = filtered.filter(prof => !prof.has_scheduling_access);
      } else if (filterStatus === 'expired_access') {
        filtered = filtered.filter(prof => 
          prof.has_scheduling_access && 
          prof.access_expires_at && 
          new Date(prof.access_expires_at) < new Date()
        );
      }
    }

    setFilteredProfessionals(filtered);
  }, [professionals, searchTerm, filterStatus]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Fetch professionals with their scheduling access status
      const response = await fetch(`${apiUrl}/api/admin/professionals-scheduling-access`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        throw new Error('Falha ao carregar profissionais');
      }

      const data = await response.json();
      setProfessionals(data);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  const openGrantModal = (professional: Professional) => {
    setModalMode('grant');
    setSelectedProfessional(professional);
    
    // Set default expiry to 3 months from now
    const defaultExpiry = new Date();
    defaultExpiry.setMonth(defaultExpiry.getMonth() + 3);
    setExpiryDate(defaultExpiry.toISOString().split('T')[0]);
    
    setReason('');
    setIsModalOpen(true);
  };

  const openExtendModal = (professional: Professional) => {
    setModalMode('extend');
    setSelectedProfessional(professional);
    
    // Set default expiry to 3 months from current expiry or now
    const currentExpiry = professional.access_expires_at ? new Date(professional.access_expires_at) : new Date();
    const defaultExpiry = new Date(currentExpiry);
    defaultExpiry.setMonth(defaultExpiry.getMonth() + 3);
    setExpiryDate(defaultExpiry.toISOString().split('T')[0]);
    
    setReason('');
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setSelectedProfessional(null);
    setExpiryDate('');
    setReason('');
    setError('');
    setSuccess('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (!selectedProfessional || !expiryDate) return;

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/admin/grant-scheduling-access`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          professional_id: selectedProfessional.id,
          expires_at: expiryDate,
          reason: reason || null
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao conceder acesso');
      }

      await fetchData();
      setSuccess(
        modalMode === 'grant' 
          ? 'Acesso à agenda concedido com sucesso!' 
          : 'Acesso à agenda estendido com sucesso!'
      );

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao processar solicitação');
    }
  };

  const confirmRevoke = (professional: Professional) => {
    setProfessionalToRevoke(professional);
    setShowRevokeConfirm(true);
  };

  const cancelRevoke = () => {
    setProfessionalToRevoke(null);
    setShowRevokeConfirm(false);
  };

  const revokeAccess = async () => {
    if (!professionalToRevoke) return;

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/admin/revoke-scheduling-access`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          professional_id: professionalToRevoke.id
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao revogar acesso');
      }

      await fetchData();
      setSuccess('Acesso à agenda revogado com sucesso!');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao revogar acesso');
    } finally {
      setProfessionalToRevoke(null);
      setShowRevokeConfirm(false);
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  };

  const formatDateTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getAccessStatusDisplay = (professional: Professional) => {
    if (!professional.has_scheduling_access) {
      return {
        text: 'Sem Acesso',
        className: 'bg-gray-100 text-gray-800',
        icon: null
      };
    }

    if (professional.access_expires_at) {
      const expiryDate = new Date(professional.access_expires_at);
      const now = new Date();
      
      if (expiryDate < now) {
        return {
          text: 'Acesso Expirado',
          className: 'bg-red-100 text-red-800',
          icon: <AlertCircle className="h-3 w-3 mr-1" />
        };
      } else {
        return {
          text: 'Acesso Ativo',
          className: 'bg-green-100 text-green-800',
          icon: <Gift className="h-3 w-3 mr-1" />
        };
      }
    }

    return {
      text: 'Acesso Ativo',
      className: 'bg-green-100 text-green-800',
      icon: <Gift className="h-3 w-3 mr-1" />
    };
  };

  const resetFilters = () => {
    setSearchTerm('');
    setFilterStatus('');
  };

  const activeAccessCount = professionals.filter(p => 
    p.has_scheduling_access && 
    (!p.access_expires_at || new Date(p.access_expires_at) > new Date())
  ).length;

  const expiredAccessCount = professionals.filter(p => 
    p.has_scheduling_access && 
    p.access_expires_at && 
    new Date(p.access_expires_at) < new Date()
  ).length;

  const noAccessCount = professionals.filter(p => !p.has_scheduling_access).length;

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Gerenciar Acesso à Agenda</h1>
          <p className="text-gray-600">Conceda acesso gratuito à agenda para atrair novos profissionais</p>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center mb-4">
          <Filter className="h-5 w-5 text-red-600 mr-2" />
          <h2 className="text-lg font-semibold">Filtros</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por nome ou email..."
              className="input pl-10"
            />
          </div>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="input"
          >
            <option value="">Todos os profissionais</option>
            <option value="with_access">Com acesso à agenda</option>
            <option value="without_access">Sem acesso à agenda</option>
            <option value="expired_access">Acesso expirado</option>
          </select>

          <button
            onClick={resetFilters}
            className="btn btn-secondary"
          >
            Limpar Filtros
          </button>
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

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">Total de Profissionais</h3>
            <UserCheck className="h-5 w-5 text-blue-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {professionals.length}
          </p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">Com Acesso Ativo</h3>
            <Gift className="h-5 w-5 text-green-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {activeAccessCount}
          </p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">Acesso Expirado</h3>
            <AlertCircle className="h-5 w-5 text-red-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {expiredAccessCount}
          </p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">Sem Acesso</h3>
            <Clock className="h-5 w-5 text-gray-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {noAccessCount}
          </p>
        </div>
      </div>

      {/* Professionals Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando profissionais...</p>
          </div>
        ) : filteredProfessionals.length === 0 ? (
          <div className="text-center py-12">
            <UserCheck className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchTerm || filterStatus ? 'Nenhum profissional encontrado' : 'Nenhum profissional cadastrado'}
            </h3>
            <p className="text-gray-600">
              {searchTerm || filterStatus
                ? 'Tente ajustar os filtros de busca.'
                : 'Cadastre profissionais primeiro para gerenciar o acesso à agenda.'
              }
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Profissional
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Categoria
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status do Acesso
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Expira em
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Concedido por
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredProfessionals.map((professional) => {
                  const statusInfo = getAccessStatusDisplay(professional);
                  return (
                    <tr key={professional.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10">
                            <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                              <UserCheck className="h-5 w-5 text-red-600" />
                            </div>
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">
                              {professional.name}
                            </div>
                            <div className="text-sm text-gray-500">
                              {professional.email}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-900">
                          {professional.category_name}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 text-xs font-medium rounded-full flex items-center w-fit ${statusInfo.className}`}>
                          {statusInfo.icon}
                          {statusInfo.text}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {professional.access_expires_at 
                          ? formatDate(professional.access_expires_at)
                          : '-'
                        }
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {professional.access_granted_by || '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          {!professional.has_scheduling_access ? (
                            <button
                              onClick={() => openGrantModal(professional)}
                              className="text-green-600 hover:text-green-900 flex items-center"
                              title="Conceder Acesso"
                            >
                              <Gift className="h-4 w-4 mr-1" />
                              Conceder
                            </button>
                          ) : (
                            <>
                              <button
                                onClick={() => openExtendModal(professional)}
                                className="text-blue-600 hover:text-blue-900 flex items-center"
                                title="Estender Acesso"
                              >
                                <Clock className="h-4 w-4 mr-1" />
                                Estender
                              </button>
                              <button
                                onClick={() => confirmRevoke(professional)}
                                className="text-red-600 hover:text-red-900 flex items-center"
                                title="Revogar Acesso"
                              >
                                <Trash2 className="h-4 w-4 mr-1" />
                                Revogar
                              </button>
                            </>
                          )}
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

      {/* Grant/Extend Access Modal */}
      {isModalOpen && selectedProfessional && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold flex items-center">
                <Gift className="h-6 w-6 text-green-600 mr-2" />
                {modalMode === 'grant' ? 'Conceder Acesso à Agenda' : 'Estender Acesso à Agenda'}
              </h2>
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
              <div className="mb-4">
                <p className="text-gray-700 mb-2">
                  <span className="font-medium">Profissional:</span> {selectedProfessional.name}
                </p>
                <p className="text-gray-700 mb-4">
                  <span className="font-medium">Categoria:</span> {selectedProfessional.category_name}
                </p>
                
                {modalMode === 'extend' && selectedProfessional.access_expires_at && (
                  <p className="text-gray-700 mb-4">
                    <span className="font-medium">Expira atualmente em:</span> {formatDate(selectedProfessional.access_expires_at)}
                  </p>
                )}
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data de Expiração *
                  </label>
                  <input
                    type="date"
                    value={expiryDate}
                    onChange={(e) => setExpiryDate(e.target.value)}
                    className="input"
                    min={new Date().toISOString().split('T')[0]}
                    required
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    O acesso ficará ativo até a data selecionada
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Motivo/Observações (opcional)
                  </label>
                  <textarea
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    className="input min-h-[80px]"
                    placeholder="Ex: Profissional em período de teste, parceria especial, etc."
                  />
                </div>
              </div>

              <div className="bg-blue-50 p-4 rounded-lg mt-4">
                <h4 className="font-medium text-blue-900 mb-2">O que está incluído:</h4>
                <ul className="text-sm text-blue-700 space-y-1">
                  <li>• Acesso completo ao sistema de agendamentos</li>
                  <li>• Gestão de pacientes particulares</li>
                  <li>• Prontuários médicos digitais</li>
                  <li>• Geração de documentos médicos</li>
                  <li>• Relatórios detalhados</li>
                </ul>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary flex items-center">
                  <Gift className="h-5 w-5 mr-2" />
                  {modalMode === 'grant' ? 'Conceder Acesso' : 'Estender Acesso'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke confirmation modal */}
      {showRevokeConfirm && professionalToRevoke && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <AlertCircle className="h-6 w-6 text-red-600 mr-2" />
              Confirmar Revogação
            </h2>
            
            <p className="mb-6">
              Tem certeza que deseja revogar o acesso à agenda do profissional{' '}
              <strong>{professionalToRevoke.name}</strong>?
            </p>
            
            <div className="bg-yellow-50 p-3 rounded-lg mb-6">
              <p className="text-yellow-700 text-sm">
                <strong>Atenção:</strong> O profissional perderá imediatamente o acesso ao sistema de agendamentos,
                mas manterá acesso aos outros recursos do sistema.
              </p>
            </div>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelRevoke}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={revokeAccess}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Check className="h-4 w-4 mr-2" />
                Revogar Acesso
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ManageSchedulingAccessPage;