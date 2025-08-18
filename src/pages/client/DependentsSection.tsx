import React, { useState, useEffect } from 'react';
import { UserPlus, Edit, Trash2, User, Check, X, CreditCard } from 'lucide-react';

type Dependent = {
  id: number;
  name: string;
  cpf: string;
  birth_date: string;
  created_at: string;
  subscription_status: string;
  subscription_expiry: string | null;
  billing_amount: number;
  payment_reference: string | null;
  activated_at: string | null;
};

type DependentsSectionProps = {
  clientId: number;
};

const DependentsSection: React.FC<DependentsSectionProps> = ({ clientId }) => {
  const [dependents, setDependents] = useState<Dependent[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedDependent, setSelectedDependent] = useState<Dependent | null>(null);
  
  // Form state
  const [name, setName] = useState('');
  const [cpf, setCpf] = useState('');
  const [birthDate, setBirthDate] = useState('');
  
  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [dependentToDelete, setDependentToDelete] = useState<Dependent | null>(null);
  
  // Payment state
  const [isCreatingPayment, setIsCreatingPayment] = useState<number | null>(null);
  const [paymentError, setPaymentError] = useState('');

  // Get API URL with fallback
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }
    
    return 'http://localhost:3001';
  };
  
  useEffect(() => {
    fetchDependents();
  }, [clientId]);
  
  const fetchDependents = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      console.log('🔄 Fetching dependents from:', `${apiUrl}/api/dependents/${clientId}`);
      
      const response = await fetch(`${apiUrl}/api/dependents/${clientId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      console.log('📡 Dependents response status:', response.status);
      
      if (response.ok) {
        const data = await response.json();
        console.log('✅ Dependents loaded:', data.length);
        setDependents(data);
      } else {
        console.warn('⚠️ Dependents not available:', response.status);
        setDependents([]);
      }
    } catch (error) {
      console.error('❌ Error fetching dependents:', error);
      setError('Não foi possível carregar os dependentes. Tente novamente.');
      setDependents([]);
    } finally {
      setIsLoading(false);
    }
  };
  
  const openCreateModal = () => {
    setModalMode('create');
    setName('');
    setCpf('');
    setBirthDate('');
    setSelectedDependent(null);
    setIsModalOpen(true);
  };
  
  const openEditModal = (dependent: Dependent) => {
    setModalMode('edit');
    setName(dependent.name);
    setCpf(dependent.cpf);
    setBirthDate(dependent.birth_date);
    setSelectedDependent(dependent);
    setIsModalOpen(true);
  };
  
  const closeModal = () => {
    setIsModalOpen(false);
    setSuccess('');
    setError('');
  };
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      if (modalMode === 'create') {
        // Validate CPF format
        if (!/^\d{11}$/.test(cpf.replace(/\D/g, ''))) {
          setError('CPF deve conter 11 dígitos numéricos');
          return;
        }
        
        // Create dependent
        const response = await fetch(`${apiUrl}/api/dependents`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            client_id: clientId,
            name,
            cpf: cpf.replace(/\D/g, ''),
            birth_date: birthDate,
          }),
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao criar dependente');
        }
        
        setSuccess('Dependente adicionado com sucesso!');
        
        // Show info about payment requirement
        setTimeout(() => {
          setSuccess('Dependente adicionado! Para ativá-lo, é necessário realizar o pagamento individual.');
        }, 1500);
      } else if (modalMode === 'edit' && selectedDependent) {
        // Update dependent
        const response = await fetch(`${apiUrl}/api/dependents/${selectedDependent.id}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name,
            birth_date: birthDate,
          }),
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao atualizar dependente');
        }
        
        setSuccess('Dependente atualizado com sucesso!');
      }
      
      // Refresh dependents list
      await fetchDependents();
      
      // Close modal after short delay
      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Ocorreu um erro ao processar a solicitação');
      }
    }
  };
  
  const createDependentPayment = async (dependentId: number) => {
    try {
      setIsCreatingPayment(dependentId);
      setPaymentError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/dependents/${dependentId}/create-payment`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao criar pagamento');
      }
      
      const data = await response.json();
      
      // Redirect to MercadoPago
      window.open(data.init_point, '_blank');
      
    } catch (error) {
      console.error('Error creating dependent payment:', error);
      setPaymentError(error instanceof Error ? error.message : 'Erro ao processar pagamento');
    } finally {
      setIsCreatingPayment(null);
    }
  };
  
  const getStatusDisplay = (dependent: Dependent) => {
    switch (dependent.subscription_status) {
      case 'active':
        return {
          text: 'Ativo',
          className: 'bg-green-100 text-green-800',
          showPayButton: false
        };
      case 'pending':
        return {
          text: 'Aguardando Pagamento',
          className: 'bg-yellow-100 text-yellow-800',
          showPayButton: true
        };
      case 'expired':
        return {
          text: 'Vencido',
          className: 'bg-red-100 text-red-800',
          showPayButton: true
        };
      default:
        return {
          text: 'Inativo',
          className: 'bg-gray-100 text-gray-800',
          showPayButton: true
        };
    }
  };
  
  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
  };
  
  const confirmDelete = (dependent: Dependent) => {
    setDependentToDelete(dependent);
    setShowDeleteConfirm(true);
  };
  
  const cancelDelete = () => {
    setDependentToDelete(null);
    setShowDeleteConfirm(false);
  };
  
  const deleteDependent = async () => {
    if (!dependentToDelete) return;
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/dependents/${dependentToDelete.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao excluir dependente');
      }
      
      // Refresh dependents list
      await fetchDependents();
      
      setSuccess('Dependente excluído com sucesso!');
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Ocorreu um erro ao excluir o dependente');
      }
    } finally {
      setDependentToDelete(null);
      setShowDeleteConfirm(false);
    }
  };
  
  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    setCpf(limitedValue);
  };
  
  const formattedCpf = (cpfValue: string) => {
    return cpfValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
  };
  
  const formatDate = (dateString: string) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
  };
  
  return (
    <div className="card mb-6">
      <div className="flex justify-between items-center mb-4">
        <div className="flex items-center">
          <User className="h-6 w-6 text-red-600 mr-2" />
          <h2 className="text-xl font-semibold">Dependentes</h2>
        </div>
        
        {dependents.length < 10 && (
          <button
            onClick={openCreateModal}
            className="btn btn-primary flex items-center"
          >
            <UserPlus className="h-5 w-5 mr-2" />
            Adicionar Dependente
          </button>
        )}
      </div>
      
      {paymentError && (
        <div className="bg-red-50 text-red-600 p-4 rounded-md mb-4">
          {paymentError}
        </div>
      )}
      
      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-md mb-4">
          {error}
        </div>
      )}
      
      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-md mb-4">
          {success}
        </div>
      )}
      
      {isLoading ? (
        <div className="text-center py-8">
          <p className="text-gray-600">Carregando dependentes...</p>
        </div>
      ) : dependents.length === 0 ? (
        <div className="text-center py-8 bg-gray-50 rounded-lg">
          <p className="text-gray-600 mb-2">Você ainda não possui dependentes cadastrados.</p>
          <p className="text-sm text-gray-500">
            Cada dependente terá cobrança individual de {formatCurrency(50)} para ativação.
          </p>
        </div>
      ) : (
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Nome</th>
                <th>CPF</th>
                <th>Status</th>
                <th>Valor</th>
                <th>Data de Nascimento</th>
                <th>Data de Cadastro</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              {dependents.map((dependent) => {
                const statusInfo = getStatusDisplay(dependent);
                return (
                  <tr key={dependent.id}>
                    <td className="flex items-center">
                      <User className="h-5 w-5 mr-2 text-gray-500" />
                      {dependent.name}
                    </td>
                    <td>{formattedCpf(dependent.cpf)}</td>
                    <td>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusInfo.className}`}>
                        {statusInfo.text}
                      </span>
                      {dependent.subscription_expiry && dependent.subscription_status === 'active' && (
                        <div className="text-xs text-gray-500 mt-1">
                          Expira em: {formatDate(dependent.subscription_expiry)}
                        </div>
                      )}
                    </td>
                    <td>
                      {formatCurrency(dependent.billing_amount || 50)}
                    </td>
                    <td>{formatDate(dependent.birth_date)}</td>
                    <td>{formatDate(dependent.created_at)}</td>
                    <td>
                      <div className="flex space-x-2">
                        {statusInfo.showPayButton && (
                          <button
                            onClick={() => createDependentPayment(dependent.id)}
                            className={`p-1 text-green-600 hover:text-green-800 ${
                              isCreatingPayment === dependent.id ? 'opacity-50 cursor-not-allowed' : ''
                            }`}
                            title="Realizar Pagamento"
                            disabled={isCreatingPayment === dependent.id}
                          >
                            {isCreatingPayment === dependent.id ? (
                              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-green-600"></div>
                            ) : (
                              <CreditCard className="h-5 w-5" />
                            )}
                          </button>
                        )}
                        <button
                          onClick={() => openEditModal(dependent)}
                          className="p-1 text-blue-600 hover:text-blue-800"
                          title="Editar"
                        >
                          <Edit className="h-5 w-5" />
                        </button>
                        <button
                          onClick={() => confirmDelete(dependent)}
                          className="p-1 text-red-600 hover:text-red-800"
                          title="Excluir"
                        >
                          <Trash2 className="h-5 w-5" />
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
      
      {/* Summary */}
      {dependents.length > 0 && (
        <div className="mt-4 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <h4 className="font-medium text-blue-900 mb-2">Resumo dos Dependentes</h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div className="text-center">
              <div className="text-lg font-bold text-green-600">
                {dependents.filter(d => d.subscription_status === 'active').length}
              </div>
              <div className="text-green-700">Ativos</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-yellow-600">
                {dependents.filter(d => d.subscription_status === 'pending').length}
              </div>
              <div className="text-yellow-700">Aguardando</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-red-600">
                {dependents.filter(d => d.subscription_status === 'expired').length}
              </div>
              <div className="text-red-700">Vencidos</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-blue-600">
                {formatCurrency(dependents.filter(d => d.subscription_status === 'pending').length * 50)}
              </div>
              <div className="text-blue-700">Total Pendente</div>
            </div>
          </div>
        </div>
      )}
      
      {/* Dependent form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">
                {modalMode === 'create' ? 'Adicionar Dependente' : 'Editar Dependente'}
              </h2>
              <button
                onClick={closeModal}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            {error && (
              <div className="bg-red-50 text-red-600 p-3 rounded-md mb-4">
                {error}
              </div>
            )}
            
            {success && (
              <div className="bg-green-50 text-green-600 p-3 rounded-md mb-4">
                {success}
              </div>
            )}
            
            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-1">
                  Nome
                </label>
                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="input"
                  required
                />
              </div>
              
              {modalMode === 'create' && (
                <div className="mb-4">
                  <label htmlFor="cpf" className="block text-sm font-medium text-gray-700 mb-1">
                    CPF
                  </label>
                  <input
                    id="cpf"
                    type="text"
                    value={cpf ? formattedCpf(cpf) : ''}
                    onChange={(e) => formatCpf(e.target.value)}
                    placeholder="000.000.000-00"
                    className="input"
                    required
                  />
                </div>
              )}
              
              <div className="mb-6">
                <label htmlFor="birthDate" className="block text-sm font-medium text-gray-700 mb-1">
                  Data de Nascimento
                </label>
                <input
                  id="birthDate"
                  type="date"
                  value={birthDate}
                  onChange={(e) => setBirthDate(e.target.value)}
                  className="input"
                  required
                />
              </div>
              
              {modalMode === 'create' && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
                  <h4 className="font-medium text-yellow-900 mb-2">Informações Importantes</h4>
                  <ul className="text-sm text-yellow-800 space-y-1">
                    <li>• Cada dependente tem cobrança individual de {formatCurrency(50)}</li>
                    <li>• O dependente só ficará ativo após confirmação do pagamento</li>
                    <li>• O pagamento pode ser feito imediatamente após o cadastro</li>
                  </ul>
                </div>
              )}
              
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary mr-2"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {modalMode === 'create' ? 'Adicionar' : 'Salvar Alterações'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      
      {/* Delete confirmation modal */}
      {showDeleteConfirm && dependentToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir o dependente <strong>{dependentToDelete.name}</strong>?
              Esta ação não pode ser desfeita.
            </p>
            
            <div className="flex justify-end">
              <button
                onClick={cancelDelete}
                className="btn btn-secondary mr-2 flex items-center"
              >
                <X className="h-5 w-5 mr-1" />
                Cancelar
              </button>
              <button
                onClick={deleteDependent}
                className="btn bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 flex items-center"
              >
                <Check className="h-5 w-5 mr-1" />
                Confirmar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DependentsSection;