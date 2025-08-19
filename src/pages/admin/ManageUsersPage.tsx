import React, { useState, useEffect } from 'react';
import { UserPlus, Edit, Trash2, User, Search, Filter, Users, Shield, Briefcase, Check, X, UserCheck, Clock, AlertCircle, Eye, EyeOff } from 'lucide-react';

type User = {
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
  zip_code: string;
  category_name: string;
  professional_percentage: number;
  roles: string[];
  subscription_status: string;
  subscription_expiry: string | null;
  created_at: string;
};

type Dependent = {
  id: number;
  client_id: number;
  name: string;
  cpf: string;
  birth_date: string;
  subscription_status: string;
  subscription_expiry: string | null;
  billing_amount: number;
  client_name: string;
  client_status: string;
  current_status: string;
  activated_at: string | null;
  created_at: string;
};

type Category = {
  id: number;
  name: string;
  description: string;
};
const ManageUsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [dependents, setDependents] = useState<Dependent[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [filteredDependents, setFilteredDependents] = useState<Dependent[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'users' | 'dependents'>('users');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  
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
  const [zipCode, setZipCode] = useState('');
  const [categoryId, setCategoryId] = useState('');
  const [professionalPercentage, setProfessionalPercentage] = useState('50');
  const [password, setPassword] = useState('');
  const [roles, setRoles] = useState<string[]>(['client']);
  
  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);
  
  // Dependent activation state
  const [isActivating, setIsActivating] = useState<number | null>(null);
  
  // Password visibility
  const [showPassword, setShowPassword] = useState(false);

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
    // Filter users
    let filtered = users;

    if (searchTerm) {
      filtered = filtered.filter(user =>
        user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.cpf?.includes(searchTerm.replace(/\D/g, '')) ||
        user.email?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (roleFilter) {
      filtered = filtered.filter(user => user.roles.includes(roleFilter));
    }

    if (statusFilter) {
      filtered = filtered.filter(user => user.subscription_status === statusFilter);
    }

    setFilteredUsers(filtered);
  }, [users, searchTerm, roleFilter, statusFilter]);

  useEffect(() => {
    // Filter dependents
    let filtered = dependents;

    if (searchTerm) {
      filtered = filtered.filter(dependent =>
        dependent.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        dependent.cpf?.includes(searchTerm.replace(/\D/g, '')) ||
        dependent.client_name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (statusFilter) {
      filtered = filtered.filter(dependent => dependent.current_status === statusFilter);
    }

    setFilteredDependents(filtered);
  }, [dependents, searchTerm, statusFilter]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Fetch users
      const usersResponse = await fetch(`${apiUrl}/api/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!usersResponse.ok) {
        throw new Error('Falha ao carregar usuários');
      }

      const usersData = await usersResponse.json();
      setUsers(usersData);

      // Fetch dependents
      const dependentsResponse = await fetch(`${apiUrl}/api/admin/dependents`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (dependentsResponse.ok) {
        const dependentsData = await dependentsResponse.json();
        setDependents(dependentsData);
      } else {
        console.warn('Dependents not available');
        setDependents([]);
      }

      // Fetch categories for professional users
      const categoriesResponse = await fetch(`${apiUrl}/api/service-categories`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (categoriesResponse.ok) {
        const categoriesData = await categoriesResponse.json();
        setCategories(categoriesData);
      } else {
        console.warn('Categories not available');
        setCategories([]);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  const activateDependent = async (dependentId: number) => {
    try {
      setIsActivating(dependentId);
      setError('');
      setSuccess('');

      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/admin/dependents/${dependentId}/activate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao ativar dependente');
      }

      await fetchData();
      setSuccess('Dependente ativado com sucesso!');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao ativar dependente');
    } finally {
      setIsActivating(null);
    }
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
    setZipCode('');
    setCategoryId('');
    setProfessionalPercentage('50');
    setPassword('');
    setRoles(['client']);
    setSelectedUser(null);
    setIsModalOpen(true);
  };

  const openEditModal = (user: User) => {
    setModalMode('edit');
    setName(user.name);
    setCpf(user.cpf || '');
    setEmail(user.email || '');
    setPhone(user.phone || '');
    setBirthDate(user.birth_date || '');
    setAddress(user.address || '');
    setAddressNumber(user.address_number || '');
    setAddressComplement(user.address_complement || '');
    setNeighborhood(user.neighborhood || '');
    setCity(user.city || '');
    setState(user.state || '');
    setZipCode(user.zip_code || '');
    setCategoryId(''); // Will need to be fetched from user data
    setProfessionalPercentage(user.professional_percentage?.toString() || '50');
    setPassword('');
    setRoles(user.roles);
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
        // Create user
        const response = await fetch(`${apiUrl}/api/users`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name,
            cpf: cpf.replace(/\D/g, '') || null,
            email: email || null,
            phone: phone.replace(/\D/g, '') || null,
            password,
            roles,
          }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao criar usuário');
        }

        setSuccess('Usuário criado com sucesso!');
      } else if (modalMode === 'edit' && selectedUser) {
        // Update user
        const updateData: any = {
          name,
          email: email || null,
          phone: phone.replace(/\D/g, '') || null,
          birth_date: birthDate || null,
          address: address || null,
          address_number: addressNumber || null,
          address_complement: addressComplement || null,
          neighborhood: neighborhood || null,
          city: city || null,
          state: state || null,
          zip_code: zipCode.replace(/\D/g, '') || null,
          category_id: roles.includes('professional') && categoryId ? parseInt(categoryId) : null,
          professional_percentage: roles.includes('professional') ? parseInt(professionalPercentage) : null,
          birth_date: birthDate || null,
          address: address || null,
          address_number: addressNumber || null,
          address_complement: addressComplement || null,
          neighborhood: neighborhood || null,
          city: city || null,
          state: state || null,
          zip_code: zipCode.replace(/\D/g, '') || null,
          category_id: roles.includes('professional') && categoryId ? parseInt(categoryId) : null,
          professional_percentage: roles.includes('professional') ? parseInt(professionalPercentage) : null,
          roles,
        };

        if (password) {
          updateData.password = password;
        }

        const response = await fetch(`${apiUrl}/api/users/${selectedUser.id}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(updateData),
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

  const confirmDelete = (user: User) => {
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

  const formatCpf = (cpf: string) => {
    if (!cpf) return '';
    return cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
  };

  const formatPhone = (phone: string) => {
    if (!phone) return '';
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length === 11) {
      return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 7)}-${cleaned.slice(7)}`;
    } else if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 6)}-${cleaned.slice(6)}`;
    }
    return phone;
  };

  const formatZipCode = (zipCode: string) => {
    if (!zipCode) return '';
    return zipCode.replace(/(\d{5})(\d{3})/, '$1-$2');
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  };

  const getRoleInfo = (roles: string[]) => {
    const roleLabels = roles.map(role => {
      switch (role) {
        case 'client': return 'Cliente';
        case 'professional': return 'Profissional';
        case 'admin': return 'Admin';
        default: return role;
      }
    });
    return roleLabels.join(', ');
  };

  const getStatusInfo = (status: string) => {
    switch (status) {
      case 'active':
        return { text: 'Ativo', className: 'bg-green-100 text-green-800' };
      case 'pending':
        return { text: 'Pendente', className: 'bg-yellow-100 text-yellow-800' };
      case 'expired':
        return { text: 'Vencido', className: 'bg-red-100 text-red-800' };
      default:
        return { text: 'Inativo', className: 'bg-gray-100 text-gray-800' };
    }
  };

  const resetFilters = () => {
    setSearchTerm('');
    setRoleFilter('');
    setStatusFilter('');
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat('pt-BR', {
      style: 'currency',
      currency: 'BRL',
    }).format(value);
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

      {/* Tab Navigation */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 mb-6">
        <div className="flex border-b border-gray-200">
          <button
            onClick={() => setActiveTab('users')}
            className={`px-6 py-4 font-medium text-sm border-b-2 transition-colors ${
              activeTab === 'users'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <User className="h-5 w-5 inline mr-2" />
            Usuários ({users.length})
          </button>
          <button
            onClick={() => setActiveTab('dependents')}
            className={`px-6 py-4 font-medium text-sm border-b-2 transition-colors ${
              activeTab === 'dependents'
                ? 'border-red-600 text-red-600'
                : 'border-transparent text-gray-500 hover:text-gray-700'
            }`}
          >
            <Users className="h-5 w-5 inline mr-2" />
            Dependentes ({dependents.length})
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center mb-4">
          <Filter className="h-5 w-5 text-red-600 mr-2" />
          <h2 className="text-lg font-semibold">Filtros</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por nome, CPF ou email..."
              className="input pl-10"
            />
          </div>

          {activeTab === 'users' && (
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="input"
            >
              <option value="">Todas as funções</option>
              <option value="client">Clientes</option>
              <option value="professional">Profissionais</option>
              <option value="admin">Administradores</option>
            </select>
          )}

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input"
          >
            <option value="">Todos os status</option>
            <option value="active">Ativo</option>
            <option value="pending">Pendente</option>
            <option value="expired">Vencido</option>
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

      {/* Users Tab */}
      {activeTab === 'users' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100">
          {isLoading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Carregando usuários...</p>
            </div>
          ) : filteredUsers.length === 0 ? (
            <div className="text-center py-12">
              <User className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                {searchTerm || roleFilter || statusFilter ? 'Nenhum usuário encontrado' : 'Nenhum usuário cadastrado'}
              </h3>
              <p className="text-gray-600">
                {searchTerm || roleFilter || statusFilter
                  ? 'Tente ajustar os filtros de busca.'
                  : 'Comece adicionando o primeiro usuário.'
                }
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Usuário
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Contato
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Endereço
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Funções
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Data de Cadastro
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Ações
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredUsers.map((user) => {
                    const statusInfo = getStatusInfo(user.subscription_status);
                    return (
                      <tr key={user.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="flex-shrink-0 h-10 w-10">
                              <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                                <User className="h-5 w-5 text-red-600" />
                              </div>
                            </div>
                            <div className="ml-4">
                              <div className="text-sm font-medium text-gray-900">
                                {user.name}
                              </div>
                              {user.cpf && (
                                <div className="text-sm text-gray-500">
                                  CPF: {formatCpf(user.cpf)}
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {user.email && <div>{user.email}</div>}
                            {user.phone && <div>{formatPhone(user.phone)}</div>}
                            {!user.email && !user.phone && (
                              <span className="text-gray-400">Não informado</span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {user.address && (
                              <div>
                                {user.address}
                                {user.address_number && `, ${user.address_number}`}
                              </div>
                            )}
                            {user.city && user.state && (
                              <div className="text-xs text-gray-500">
                                {user.city}, {user.state}
                              </div>
                            )}
                            {!user.address && (
                              <span className="text-gray-400">Não informado</span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex flex-wrap gap-1">
                            {user.roles.map((role) => (
                              <span
                                key={role}
                                className={`px-2 py-1 text-xs font-medium rounded-full ${
                                  role === 'admin'
                                    ? 'bg-red-100 text-red-800'
                                    : role === 'professional'
                                    ? 'bg-blue-100 text-blue-800'
                                    : 'bg-green-100 text-green-800'
                                }`}
                              >
                                {getRoleInfo([role])}
                              </span>
                            ))}
                            {user.roles.includes('professional') && user.category_name && (
                              <div className="text-xs text-gray-500 mt-1">
                                {user.category_name} - {user.professional_percentage}%
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusInfo.className}`}>
                            {statusInfo.text}
                          </span>
                          {user.subscription_expiry && user.subscription_status === 'active' && (
                            <div className="text-xs text-gray-500 mt-1">
                              Expira: {formatDate(user.subscription_expiry)}
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          {formatDate(user.created_at)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                          <div className="flex items-center justify-end space-x-2">
                            <button
                              onClick={() => openEditModal(user)}
                              className="text-blue-600 hover:text-blue-900"
                            >
                              <Edit className="h-4 w-4" />
                            </button>
                            <button
                              onClick={() => confirmDelete(user)}
                              className="text-red-600 hover:text-red-900"
                            >
                              <Trash2 className="h-4 w-4" />
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
        </div>
      )}

      {/* Dependents Tab */}
      {activeTab === 'dependents' && (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100">
          {isLoading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Carregando dependentes...</p>
            </div>
          ) : filteredDependents.length === 0 ? (
            <div className="text-center py-12">
              <Users className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                {searchTerm || statusFilter ? 'Nenhum dependente encontrado' : 'Nenhum dependente cadastrado'}
              </h3>
              <p className="text-gray-600">
                {searchTerm || statusFilter
                  ? 'Tente ajustar os filtros de busca.'
                  : 'Dependentes são cadastrados pelos próprios clientes.'
                }
              </p>
            </div>
          ) : (
            <>
              {/* Statistics Cards for Dependents */}
              <div className="p-6 border-b border-gray-200">
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  <div className="bg-green-50 p-4 rounded-lg text-center">
                    <div className="text-2xl font-bold text-green-600">
                      {dependents.filter(d => d.current_status === 'active').length}
                    </div>
                    <div className="text-sm text-green-700">Ativos</div>
                  </div>
                  <div className="bg-yellow-50 p-4 rounded-lg text-center">
                    <div className="text-2xl font-bold text-yellow-600">
                      {dependents.filter(d => d.current_status === 'pending').length}
                    </div>
                    <div className="text-sm text-yellow-700">Aguardando Pagamento</div>
                  </div>
                  <div className="bg-red-50 p-4 rounded-lg text-center">
                    <div className="text-2xl font-bold text-red-600">
                      {dependents.filter(d => d.current_status === 'expired').length}
                    </div>
                    <div className="text-sm text-red-700">Vencidos</div>
                  </div>
                  <div className="bg-blue-50 p-4 rounded-lg text-center">
                    <div className="text-2xl font-bold text-blue-600">
                      {formatCurrency(dependents.filter(d => d.current_status === 'pending').length * 50)}
                    </div>
                    <div className="text-sm text-blue-700">Receita Pendente</div>
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Dependente
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Titular
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Status
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Valor
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Data de Cadastro
                      </th>
                      <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Ações
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {filteredDependents.map((dependent) => {
                      const statusInfo = getStatusInfo(dependent.current_status);
                      return (
                        <tr key={dependent.id} className="hover:bg-gray-50">
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="flex items-center">
                              <div className="flex-shrink-0 h-10 w-10">
                                <div className="h-10 w-10 rounded-full bg-blue-100 flex items-center justify-center">
                                  <Users className="h-5 w-5 text-blue-600" />
                                </div>
                              </div>
                              <div className="ml-4">
                                <div className="text-sm font-medium text-gray-900">
                                  {dependent.name}
                                </div>
                                <div className="text-sm text-gray-500">
                                  CPF: {formatCpf(dependent.cpf)}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <div className="text-sm text-gray-900">
                              {dependent.client_name}
                            </div>
                            <div className="text-sm text-gray-500">
                              Status: {getStatusInfo(dependent.client_status).text}
                            </div>
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap">
                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${statusInfo.className}`}>
                              {statusInfo.text}
                            </span>
                            {dependent.subscription_expiry && dependent.current_status === 'active' && (
                              <div className="text-xs text-gray-500 mt-1">
                                Expira: {formatDate(dependent.subscription_expiry)}
                              </div>
                            )}
                            {dependent.activated_at && (
                              <div className="text-xs text-gray-500 mt-1">
                                Ativado: {formatDate(dependent.activated_at)}
                              </div>
                            )}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                            {formatCurrency(dependent.billing_amount)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            {formatDate(dependent.created_at)}
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                            <div className="flex items-center justify-end space-x-2">
                              {dependent.current_status !== 'active' && (
                                <button
                                  onClick={() => activateDependent(dependent.id)}
                                  className={`text-green-600 hover:text-green-900 flex items-center ${
                                    isActivating === dependent.id ? 'opacity-50 cursor-not-allowed' : ''
                                  }`}
                                  title="Ativar Dependente"
                                  disabled={isActivating === dependent.id}
                                >
                                  {isActivating === dependent.id ? (
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-green-600"></div>
                                  ) : (
                                    <>
                                      <UserCheck className="h-4 w-4 mr-1" />
                                      Ativar
                                    </>
                                  )}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* User form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
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
              <div className="space-y-6">
                {/* Personal Information */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                    <User className="h-5 w-5 mr-2 text-red-600" />
                    Informações Pessoais
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-1">
                        Nome Completo *
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
                          CPF (opcional)
                        </label>
                        <input
                          id="cpf"
                          type="text"
                          value={formatCpf(cpf)}
                          onChange={(e) => setCpf(e.target.value.replace(/\D/g, ''))}
                          className="input"
                          placeholder="000.000.000-00"
                        />
                      </div>
                    )}

                    <div>
                      <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                        Email (opcional)
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
                        Telefone (opcional)
                      </label>
                      <input
                        id="phone"
                        type="text"
                        value={formatPhone(phone)}
                        onChange={(e) => setPhone(e.target.value.replace(/\D/g, ''))}
                        className="input"
                        placeholder="(00) 00000-0000"
                      />
                    </div>

                    <div>
                      <label htmlFor="birthDate" className="block text-sm font-medium text-gray-700 mb-1">
                        Data de Nascimento (opcional)
                      </label>
                      <input
                        id="birthDate"
                        type="date"
                        value={birthDate}
                        onChange={(e) => setBirthDate(e.target.value)}
                        className="input"
                      />
                    </div>
                  </div>
                </div>

                {/* Address Information */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Endereço (opcional)
                  </h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label htmlFor="zipCode" className="block text-sm font-medium text-gray-700 mb-1">
                        CEP
                      </label>
                      <input
                        id="zipCode"
                        type="text"
                        value={formatZipCode(zipCode)}
                        onChange={(e) => setZipCode(e.target.value.replace(/\D/g, ''))}
                        className="input"
                        placeholder="00000-000"
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
                  </div>
                </div>

                {/* Roles */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Funções no Sistema
                  </h3>
                  
                  <div className="space-y-2">
                    {['client', 'professional', 'admin'].map((role) => (
                      <label key={role} className="flex items-center">
                        <input
                          type="checkbox"
                          checked={roles.includes(role)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setRoles([...roles, role]);
                            } else {
                              setRoles(roles.filter(r => r !== role));
                              // Clear professional fields if unchecking professional
                              if (role === 'professional') {
                                setCategoryId('');
                                setProfessionalPercentage('50');
                              }
                            }
                          }}
                          className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                        />
                        <span className="ml-2 text-sm text-gray-600">
                          {getRoleInfo([role])}
                        </span>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Professional specific fields */}
                {roles.includes('professional') && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                      <Briefcase className="h-5 w-5 mr-2 text-blue-600" />
                      Informações Profissionais
                    </h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label htmlFor="categoryId" className="block text-sm font-medium text-gray-700 mb-1">
                          Categoria Profissional *
                        </label>
                        <select
                          id="categoryId"
                          value={categoryId}
                          onChange={(e) => setCategoryId(e.target.value)}
                          className="input"
                          required={roles.includes('professional')}
                        >
                          <option value="">Selecione uma categoria</option>
                          {categories.map((category) => (
                            <option key={category.id} value={category.id}>
                              {category.name}
                            </option>
                          ))}
                        </select>
                        {categories.length === 0 && (
                          <p className="text-xs text-gray-500 mt-1">
                            Nenhuma categoria disponível. Cadastre categorias primeiro.
                          </p>
                        )}
                      </div>

                      <div>
                        <label htmlFor="professionalPercentage" className="block text-sm font-medium text-gray-700 mb-1">
                          Porcentagem do Profissional (%) *
                        </label>
                        <input
                          id="professionalPercentage"
                          type="number"
                          min="0"
                          max="100"
                          value={professionalPercentage}
                          onChange={(e) => setProfessionalPercentage(e.target.value)}
                          className="input"
                          required={roles.includes('professional')}
                        />
                        <p className="text-xs text-gray-500 mt-1">
                          Porcentagem que o profissional recebe das consultas do convênio
                        </p>
                      </div>
                    </div>
                    
                    <div className="bg-blue-50 p-4 rounded-lg mt-4">
                      <h4 className="font-medium text-blue-900 mb-2">Informações sobre porcentagem:</h4>
                      <ul className="text-sm text-blue-700 space-y-1">
                        <li>• O profissional recebe a porcentagem definida das consultas do convênio</li>
                        <li>• O convênio fica com o restante (100% - porcentagem do profissional)</li>
                        <li>• Consultas particulares: profissional recebe 100%</li>
                        <li>• Padrão: 50% para o profissional, 50% para o convênio</li>
                      </ul>
                    </div>
                  </div>
                )}

                {/* Security */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Segurança
              </div>

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