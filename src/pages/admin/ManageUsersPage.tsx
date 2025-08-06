import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { UserPlus, Edit, Trash2, User, Check, X, Search, Filter, UserCheck, Calendar } from 'lucide-react';

type UserData = {
  id: number;
  name: string;
  cpf: string;
  email: string;
  phone: string;
  birth_date: string;
  address: string;
  address_number: string;
  address_complement: string;
  neighborhood: string;
  city: string;
  state: string;
  roles: string[];
  percentage?: number;
  category_id?: number;
  subscription_status?: string;
  subscription_expiry?: string;
  created_at: string;
};

type Category = {
  id: number;
  name: string;
  description: string;
};

const ManageUsersPage: React.FC = () => {
  const [users, setUsers] = useState<UserData[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedUser, setSelectedUser] = useState<UserData | null>(null);
  
  // Form state
  const [name, setName] = useState('');
  const [cpf, setCpf] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [birthDate, setBirthDate] = useState('');
  const [address, setAddress] = useState('');
  const [addressNumber, setAddressNumber] = useState('');
  const [addressComplement, setAddressComplement] = useState('');
  const [neighborhood, setNeighborhood] = useState('');
  const [city, setCity] = useState('');
  const [state, setState] = useState('');
  const [password, setPassword] = useState('');
  const [roles, setRoles] = useState<string[]>([]);
  const [percentage, setPercentage] = useState('50');
  const [categoryId, setCategoryId] = useState<string>('');
  
  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [userToDelete, setUserToDelete] = useState<UserData | null>(null);

  // New filter state
  const [filters, setFilters] = useState({
    search: '',
    role: '',
    category: '',
    state: '',
  });

  // Filtered users
  const [filteredUsers, setFilteredUsers] = useState<UserData[]>([]);

  // 🔥 NEW: Activation state
  const [isActivating, setIsActivating] = useState<number | null>(null);
  const [showActivationModal, setShowActivationModal] = useState(false);
  const [userToActivate, setUserToActivate] = useState<UserData | null>(null);
  const [expiryDate, setExpiryDate] = useState('');

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

  // Apply filters
  useEffect(() => {
    if (!users) return;

    let result = [...users];

    // Search filter (name, email, or CPF)
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      result = result.filter(user => 
        user.name.toLowerCase().includes(searchLower) ||
        user.email?.toLowerCase().includes(searchLower) ||
        user.cpf.includes(filters.search.replace(/\D/g, ''))
      );
    }

    // Role filter
    if (filters.role) {
      result = result.filter(user => 
        user.roles && user.roles.includes(filters.role)
      );
    }

    // Category filter (for professionals)
    if (filters.category) {
      result = result.filter(user => 
        user.category_id === parseInt(filters.category)
      );
    }

    // State filter
    if (filters.state) {
      result = result.filter(user => user.state === filters.state);
    }

    setFilteredUsers(result);
  }, [users, filters]);

  // Reset filters
  const resetFilters = () => {
    setFilters({
      search: '',
      role: '',
      category: '',
      state: '',
    });
  };
  
  useEffect(() => {
    fetchData();
  }, []);
  
  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      console.log('Fetching users data from:', apiUrl);
      
      // Fetch categories
      const categoriesResponse = await fetch(`${apiUrl}/api/service-categories`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (categoriesResponse.ok) {
        const categoriesData = await categoriesResponse.json();
        setCategories(categoriesData);
      }
      
      // Fetch users
      const usersResponse = await fetch(`${apiUrl}/api/users`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!usersResponse.ok) {
        throw new Error('Falha ao carregar usuários');
      }
      
      const usersData = await usersResponse.json();
      setUsers(usersData);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  // 🔥 NEW: Function to open activation modal
  const openActivationModal = (user: UserData) => {
    setUserToActivate(user);
    
    // Set default expiry date to 1 month from now
    const defaultExpiry = new Date();
    defaultExpiry.setMonth(defaultExpiry.getMonth() + 1);
    setExpiryDate(defaultExpiry.toISOString().split('T')[0]);
    
    setShowActivationModal(true);
  };

  // 🔥 NEW: Function to activate client with custom expiry date
  const activateClient = async () => {
    if (!userToActivate || !expiryDate) return;
    
    try {
      setIsActivating(userToActivate.id);
      setError('');
      setSuccess('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/users/${userToActivate.id}/activate`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          expiry_date: expiryDate
        }),
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao ativar cliente');
      }
      
      // Close modal and refresh data
      setShowActivationModal(false);
      setUserToActivate(null);
      setExpiryDate('');
      
      // Refresh users list
      await fetchData();
      
      setSuccess('Cliente ativado com sucesso!');
      
      // Clear success message after 3 seconds
      setTimeout(() => {
        setSuccess('');
      }, 3000);
    } catch (error) {
      console.error('Error activating client:', error);
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Ocorreu um erro ao ativar o cliente');
      }
    } finally {
      setIsActivating(null);
    }
  };

  // 🔥 NEW: Function to cancel activation
  const cancelActivation = () => {
    setShowActivationModal(false);
    setUserToActivate(null);
    setExpiryDate('');
  };
  
  const openCreateModal = () => {
    setModalMode('create');
    setName('');
    setCpf('');
    setEmail('');
    setPhone('');
    setBirthDate('');
    setAddress('');
    setAddressNumber('');
    setAddressComplement('');
    setNeighborhood('');
    setCity('');
    setState('');
    setPassword('');
    setRoles([]);
    setPercentage('50');
    setCategoryId('');
    setSelectedUser(null);
    setIsModalOpen(true);
  };
  
  const openEditModal = (user: UserData) => {
    setModalMode('edit');
    setName(user.name);
    setEmail(user.email || '');
    setPhone(user.phone || '');
    setBirthDate(user.birth_date || '');
    setAddress(user.address || '');
    setAddressNumber(user.address_number || '');
    setAddressComplement(user.address_complement || '');
    setNeighborhood(user.neighborhood || '');
    setCity(user.city || '');
    setState(user.state || '');
    setRoles(user.roles || []);
    setPercentage(user.percentage?.toString() || '50');
    setCategoryId(user.category_id?.toString() || '');
    setSelectedUser(user);
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
        
        // Validate roles
        if (roles.length === 0) {
          setError('Pelo menos uma role deve ser selecionada');
          return;
        }
        
        // Validate category for professionals
        if (roles.includes('professional') && !categoryId) {
          setError('É necessário selecionar uma categoria para profissionais');
          return;
        }
        
        // Create user
        const response = await fetch(`${apiUrl}/api/users`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name,
            cpf: cpf.replace(/\D/g, ''),
            email,
            phone,
            birth_date: birthDate,
            address,
            address_number: addressNumber,
            address_complement: addressComplement,
            neighborhood,
            city,
            state,
            password,
            roles,
            percentage: roles.includes('professional') ? Number(percentage) : null,
            category_id: roles.includes('professional') ? Number(categoryId) : null,
          }),
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao criar usuário');
        }
        
        setSuccess('Usuário criado com sucesso!');
      } else if (modalMode === 'edit' && selectedUser) {
        // Validate roles
        if (roles.length === 0) {
          setError('Pelo menos uma role deve ser selecionada');
          return;
        }
        
        // Validate category for professionals
        if (roles.includes('professional') && !categoryId) {
          setError('É necessário selecionar uma categoria para profissionais');
          return;
        }
        
        // Update user
        const response = await fetch(`${apiUrl}/api/users/${selectedUser.id}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name,
            email,
            phone,
            birth_date: birthDate,
            address,
            address_number: addressNumber,
            address_complement: addressComplement,
            neighborhood,
            city,
            state,
            roles,
            percentage: roles.includes('professional') ? Number(percentage) : null,
            category_id: roles.includes('professional') ? Number(categoryId) : null,
          }),
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao atualizar usuário');
        }
        
        setSuccess('Usuário atualizado com sucesso!');
      }
      
      // Refresh users list
      await fetchData();
      
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
  
  const confirmDelete = (user: UserData) => {
    setUserToDelete(user);
    setShowDeleteConfirm(true);
  };
  
  const cancelDelete = () => {
    setUserToDelete(null);
    setShowDeleteConfirm(false);
  };
  
  const deleteUser = async () => {
    if (!userToDelete) return;
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/users/${userToDelete.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao excluir usuário');
      }
      
      // Refresh users list
      await fetchData();
      
      setSuccess('Usuário excluído com sucesso!');
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Ocorreu um erro ao excluir o usuário');
      }
    } finally {
      setUserToDelete(null);
      setShowDeleteConfirm(false);
    }
  };
  
  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    setCpf(limitedValue);
  };
  
  const formatPhone = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    let formattedValue = limitedValue;
    
    if (limitedValue.length > 2) {
      formattedValue = `(${limitedValue.slice(0, 2)}) ${limitedValue.slice(2)}`;
      if (limitedValue.length > 7) {
        formattedValue = `(${limitedValue.slice(0, 2)}) ${limitedValue.slice(2, 7)}-${limitedValue.slice(7)}`;
      }
    }
    
    setPhone(formattedValue);
  };
  
  const formattedCpf = (cpfValue: string) => {
    return cpfValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
  };
  
  const getRoleName = (role: string) => {
    switch (role) {
      case 'client':
        return 'Cliente';
      case 'professional':
        return 'Profissional';
      case 'admin':
        return 'Administrador';
      default:
        return role;
    }
  };
  
  const formatDate = (dateString: string) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
  };

  // 🔥 NEW: Function to get subscription status display
  const getSubscriptionStatusDisplay = (status?: string) => {
    switch (status) {
      case 'active':
        return {
          text: 'Ativo',
          className: 'bg-green-100 text-green-800'
        };
      case 'pending':
        return {
          text: 'Pendente',
          className: 'bg-yellow-100 text-yellow-800'
        };
      case 'expired':
        return {
          text: 'Vencido',
          className: 'bg-red-100 text-red-800'
        };
      default:
        return {
          text: 'N/A',
          className: 'bg-gray-100 text-gray-800'
        };
    }
  };

  const handleRoleChange = (role: string, checked: boolean) => {
    if (checked) {
      setRoles([...roles, role]);
    } else {
      setRoles(roles.filter(r => r !== role));
    }
  };
  
  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Gerenciar Usuários</h1>
          <p className="text-gray-600">Adicione, edite ou remova usuários do sistema</p>
        </div>
        
        <button
          onClick={openCreateModal}
          className="btn btn-primary flex items-center"
        >
          <UserPlus className="h-5 w-5 mr-2" />
          Novo Usuário
        </button>
      </div>

      {/* Filters section */}
      <div className="card mb-6">
        <div className="flex items-center mb-4">
          <Filter className="h-5 w-5 text-red-600 mr-2" />
          <h2 className="text-lg font-semibold">Filtros</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Buscar
            </label>
            <div className="relative">
              <input
                type="text"
                value={filters.search}
                onChange={(e) => setFilters(prev => ({ ...prev, search: e.target.value }))}
                placeholder="Nome, email ou CPF"
                className="input pl-10"
              />
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Tipo de Usuário
            </label>
            <select
              value={filters.role}
              onChange={(e) => setFilters(prev => ({ ...prev, role: e.target.value }))}
              className="input"
            >
              <option value="">Todos</option>
              <option value="client">Cliente</option>
              <option value="professional">Profissional</option>
              <option value="admin">Administrador</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Categoria
            </label>
            <select
              value={filters.category}
              onChange={(e) => setFilters(prev => ({ ...prev, category: e.target.value }))}
              className="input"
              disabled={filters.role !== 'professional'}
            >
              <option value="">Todas</option>
              {categories.map((category) => (
                <option key={category.id} value={category.id}>
                  {category.name}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Estado
            </label>
            <select
              value={filters.state}
              onChange={(e) => setFilters(prev => ({ ...prev, state: e.target.value }))}
              className="input"
            >
              <option value="">Todos</option>
              <option value="AC">Acre</option>
              <option value="AL">Alagoas</option>
              <option value="AP">Amapá</option>
              <option value="AM">Amazonas</option>
              <option value="BA">Bahia</option>
              <option value="CE">Ceará</option>
              <option value="DF">Distrito Federal</option>
              <option value="ES">Espírito Santo</option>
              <option value="GO">Goiás</option>
              <option value="MA">Maranhão</option>
              <option value="MT">Mato Grosso</option>
              <option value="MS">Mato Grosso do Sul</option>
              <option value="MG">Minas Gerais</option>
              <option value="PA">Pará</option>
              <option value="PB">Paraíba</option>
              <option value="PR">Paraná</option>
              <option value="PE">Pernambuco</option>
              <option value="PI">Piauí</option>
              <option value="RJ">Rio de Janeiro</option>
              <option value="RN">Rio Grande do Norte</option>
              <option value="RS">Rio Grande do Sul</option>
              <option value="RO">Rondônia</option>
              <option value="RR">Roraima</option>
              <option value="SC">Santa Catarina</option>
              <option value="SP">São Paulo</option>
              <option value="SE">Sergipe</option>
              <option value="TO">Tocantins</option>
            </select>
          </div>
        </div>

        <div className="flex justify-end mt-4">
          <button
            onClick={resetFilters}
            className="btn btn-secondary"
          >
            Limpar Filtros
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-md mb-6">
          {error}
        </div>
      )}
      
      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-md mb-6">
          {success}
        </div>
      )}
      
      <div className="card">
        {isLoading ? (
          <div className="text-center py-8">
            <p className="text-gray-600">Carregando usuários...</p>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="text-center py-8 bg-gray-50 rounded-lg">
            <p className="text-gray-600">Nenhum usuário encontrado.</p>
            <button
              onClick={openCreateModal}
              className="btn btn-primary mt-4 inline-flex items-center"
            >
              <UserPlus className="h-5 w-5 mr-2" />
              Adicionar Usuário
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Nome</th>
                  <th>CPF</th>
                  <th>Email</th>
                  <th>Telefone</th>
                  <th>Roles</th>
                  <th>Status Assinatura</th>
                  <th>Categoria</th>
                  <th>Porcentagem</th>
                  <th>Data de Cadastro</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map((user) => (
                  <tr key={user.id}>
                    <td className="flex items-center">
                      <User className="h-5 w-5 mr-2 text-gray-500" />
                      {user.name}
                    </td>
                    <td>{formattedCpf(user.cpf)}</td>
                    <td>{user.email || '-'}</td>
                    <td>{user.phone || '-'}</td>
                    <td>
                      <div className="flex flex-wrap gap-1">
                        {user.roles?.map((role) => (
                          <span
                            key={role}
                            className={`px-2 py-1 rounded-full text-xs font-medium ${
                              role === 'admin' 
                                ? 'bg-purple-100 text-purple-800'
                                : role === 'professional'
                                ? 'bg-blue-100 text-blue-800'
                                : 'bg-green-100 text-green-800'
                            }`}
                          >
                            {getRoleName(role)}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td>
                      {user.roles?.includes('client') ? (
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          getSubscriptionStatusDisplay(user.subscription_status).className
                        }`}>
                          {getSubscriptionStatusDisplay(user.subscription_status).text}
                        </span>
                      ) : (
                        <span className="text-gray-500">-</span>
                      )}
                    </td>
                    <td>
                      {user.roles?.includes('professional') && user.category_id
                        ? categories.find(c => c.id === user.category_id)?.name || '-'
                        : '-'}
                    </td>
                    <td>
                      {user.roles?.includes('professional') ? `${user.percentage}%` : '-'}
                    </td>
                    <td>{formatDate(user.created_at)}</td>
                    <td>
                      <div className="flex space-x-2">
                        {/* 🔥 NEW: Activate button for clients with pending status */}
                        {user.roles?.includes('client') && user.subscription_status === 'pending' && (
                          <button
                            onClick={() => openActivationModal(user)}
                            className={`p-1 text-green-600 hover:text-green-800 ${
                              isActivating === user.id ? 'opacity-50 cursor-not-allowed' : ''
                            }`}
                            title="Ativar Cliente"
                            disabled={isActivating === user.id}
                          >
                            <UserCheck className="h-5 w-5" />
                          </button>
                        )}
                        
                        <button
                          onClick={() => openEditModal(user)}
                          className="p-1 text-blue-600 hover:text-blue-800"
                          title="Editar"
                        >
                          <Edit className="h-5 w-5" />
                        </button>
                        <button
                          onClick={() => confirmDelete(user)}
                          className="p-1 text-red-600 hover:text-red-800"
                          title="Excluir"
                        >
                          <Trash2 className="h-5 w-5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 🔥 NEW: Activation modal */}
      {showActivationModal && userToActivate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold flex items-center">
                <Calendar className="h-6 w-6 text-green-600 mr-2" />
                Ativar Cliente
              </h2>
              <button
                onClick={cancelActivation}
                className="text-gray-500 hover:text-gray-700"
                disabled={isActivating === userToActivate.id}
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            
            <div className="mb-4">
              <p className="text-gray-700 mb-2">
                <span className="font-medium">Cliente:</span> {userToActivate.name}
              </p>
              <p className="text-gray-700 mb-4">
                <span className="font-medium">CPF:</span> {formattedCpf(userToActivate.cpf)}
              </p>
            </div>

            <div className="mb-6">
              <label htmlFor="expiryDate" className="block text-sm font-medium text-gray-700 mb-1">
                Data de Expiração da Assinatura *
              </label>
              <input
                id="expiryDate"
                type="date"
                value={expiryDate}
                onChange={(e) => setExpiryDate(e.target.value)}
                className="input"
                min={new Date().toISOString().split('T')[0]}
                disabled={isActivating === userToActivate.id}
                required
              />
              <p className="text-xs text-gray-500 mt-1">
                A assinatura ficará ativa até a data selecionada
              </p>
            </div>
            
            <div className="flex justify-end">
              <button
                onClick={cancelActivation}
                className="btn btn-secondary mr-2"
                disabled={isActivating === userToActivate.id}
              >
                Cancelar
              </button>
              <button
                onClick={activateClient}
                className={`btn btn-primary flex items-center ${
                  isActivating === userToActivate.id ? 'opacity-70 cursor-not-allowed' : ''
                }`}
                disabled={isActivating === userToActivate.id || !expiryDate}
              >
                {isActivating === userToActivate.id ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Ativando...
                  </>
                ) : (
                  <>
                    <UserCheck className="h-5 w-5 mr-2" />
                    Ativar Cliente
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* User form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">
                {modalMode === 'create' ? 'Adicionar Usuário' : 'Editar Usuário'}
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
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
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
                  <div>
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
                
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                    Email
                  </label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="phone" className="block text-sm font-medium text-gray-700 mb-1">
                    Telefone
                  </label>
                  <input
                    id="phone"
                    type="text"
                    value={phone}
                    onChange={(e) => formatPhone(e.target.value)}
                    placeholder="(00) 00000-0000"
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="birthDate" className="block text-sm font-medium text-gray-700 mb-1">
                    Data de Nascimento
                  </label>
                  <input
                    id="birthDate"
                    type="date"
                    value={birthDate}
                    onChange={(e) => setBirthDate(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="address" className="block text-sm font-medium text-gray-700 mb-1">
                    Endereço
                  </label>
                  <input
                    id="address"
                    type="text"
                    value={address}
                    onChange={(e) => setAddress(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="addressNumber" className="block text-sm font-medium text-gray-700 mb-1">
                    Número
                  </label>
                  <input
                    id="addressNumber"
                    type="text"
                    value={addressNumber}
                    onChange={(e) => setAddressNumber(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="addressComplement" className="block text-sm font-medium text-gray-700 mb-1">
                    Complemento
                  </label>
                  <input
                    id="addressComplement"
                    type="text"
                    value={addressComplement}
                    onChange={(e) => setAddressComplement(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="neighborhood" className="block text-sm font-medium text-gray-700 mb-1">
                    Bairro
                  </label>
                  <input
                    id="neighborhood"
                    type="text"
                    value={neighborhood}
                    onChange={(e) => setNeighborhood(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="city" className="block text-sm font-medium text-gray-700 mb-1">
                    Cidade
                  </label>
                  <input
                    id="city"
                    type="text"
                    value={city}
                    onChange={(e) => setCity(e.target.value)}
                    className="input"
                  />
                </div>
                
                <div>
                  <label htmlFor="state" className="block text-sm font-medium text-gray-700 mb-1">
                    Estado
                  </label>
                  <select
                    id="state"
                    value={state}
                    onChange={(e) => setState(e.target.value)}
                    className="input"
                  >
                    <option value="">Selecione...</option>
                    <option value="AC">Acre</option>
                    <option value="AL">Alagoas</option>
                    <option value="AP">Amapá</option>
                    <option value="AM">Amazonas</option>
                    <option value="BA">Bahia</option>
                    <option value="CE">Ceará</option>
                    <option value="DF">Distrito Federal</option>
                    <option value="ES">Espírito Santo</option>
                    <option value="GO">Goiás</option>
                    <option value="MA">Maranhão</option>
                    <option value="MT">Mato Grosso</option>
                    <option value="MS">Mato Grosso do Sul</option>
                    <option value="MG">Minas Gerais</option>
                    <option value="PA">Pará</option>
                    <option value="PB">Paraíba</option>
                    <option value="PR">Paraná</option>
                    <option value="PE">Pernambuco</option>
                    <option value="PI">Piauí</option>
                    <option value="RJ">Rio de Janeiro</option>
                    <option value="RN">Rio Grande do Norte</option>
                    <option value="RS">Rio Grande do Sul</option>
                    <option value="RO">Rondônia</option>
                    <option value="RR">Roraima</option>
                    <option value="SC">Santa Catarina</option>
                    <option value="SP">São Paulo</option>
                    <option value="SE">Sergipe</option>
                    <option value="TO">Tocantins</option>
                  </select>
                </div>
                
                {modalMode === 'create' && (
                  <div>
                    <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                      Senha
                    </label>
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input"
                      required
                    />
                  </div>
                )}
              </div>

              {/* Roles Section */}
              <div className="mt-6">
                <label className="block text-sm font-medium text-gray-700 mb-3">
                  Tipos de Acesso (Roles)
                </label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={roles.includes('client')}
                      onChange={(e) => handleRoleChange('client', e.target.checked)}
                      className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                    />
                    <span className="ml-2 text-sm text-gray-600">Cliente</span>
                  </label>
                  
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={roles.includes('professional')}
                      onChange={(e) => handleRoleChange('professional', e.target.checked)}
                      className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                    />
                    <span className="ml-2 text-sm text-gray-600">Profissional</span>
                  </label>
                  
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={roles.includes('admin')}
                      onChange={(e) => handleRoleChange('admin', e.target.checked)}
                      className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                    />
                    <span className="ml-2 text-sm text-gray-600">Administrador</span>
                  </label>
                </div>
              </div>
              
              {/* Professional specific fields */}
              {roles.includes('professional') && (
                <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label htmlFor="category" className="block text-sm font-medium text-gray-700 mb-1">
                      Categoria de Serviço
                    </label>
                    <select
                      id="category"
                      value={categoryId}
                      onChange={(e) => setCategoryId(e.target.value)}
                      className="input"
                      required
                    >
                      <option value="">Selecione uma categoria</option>
                      {categories.map((category) => (
                        <option key={category.id} value={category.id}>
                          {category.name}
                        </option>
                      ))}
                    </select>
                  </div>
                  
                  <div>
                    <label htmlFor="percentage" className="block text-sm font-medium text-gray-700 mb-1">
                      Porcentagem de Comissão (%)
                    </label>
                    <input
                      id="percentage"
                      type="number"
                      min="0"
                      max="100"
                      value={percentage}
                      onChange={(e) => setPercentage(e.target.value)}
                      className="input"
                      required
                    />
                    <p className="text-xs text-gray-500 mt-1">
                      Porcentagem que o profissional receberá do valor das consultas.
                    </p>
                  </div>
                </div>
              )}
              
              <div className="flex justify-end mt-6">
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
      {showDeleteConfirm && userToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir o usuário <strong>{userToDelete.name}</strong>?
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
                onClick={deleteUser}
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

export default ManageUsersPage;