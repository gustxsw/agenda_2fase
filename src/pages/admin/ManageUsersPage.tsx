import React, { useState, useEffect } from 'react';
import { UserPlus, Edit, Trash2, User, Search, Phone, Mail, MapPin, Calendar, X, Check, Eye, EyeOff, CheckCircle, Clock, AlertTriangle, Users } from 'lucide-react';

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
  roles: string[];
  category_name: string;
  professional_percentage: number;
  subscription_status: string;
  subscription_expiry: string;
  created_at: string;
};

type Dependent = {
  id: number;
  name: string;
  cpf: string;
  birth_date: string;
  subscription_status: string;
  subscription_expiry: string;
  created_at: string;
};

type Category = {
  id: number;
  name: string;
  description: string;
};

const ManageUsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<User[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRole, setSelectedRole] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  
  // Activation modal state
  const [isActivationModalOpen, setIsActivationModalOpen] = useState(false);
  const [userToActivate, setUserToActivate] = useState<User | null>(null);
  const [activationExpiryDate, setActivationExpiryDate] = useState('');
  const [isActivating, setIsActivating] = useState(false);
  
  // Form state
  const [formData, setFormData] = useState({
    name: '',
    cpf: '',
    email: '',
    phone: '',
    birth_date: '',
    address: '',
    address_number: '',
    address_complement: '',
    neighborhood: '',
    city: '',
    state: '',
    password: '',
    roles: [] as string[],
    category_id: '',
    professional_percentage: '50'
  });
  
  // UI state
  const [showPassword, setShowPassword] = useState(false);
  
  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [userToDelete, setUserToDelete] = useState<User | null>(null);

  // Dependents modal state
  const [isDependentsModalOpen, setIsDependentsModalOpen] = useState(false);
  const [selectedUserDependents, setSelectedUserDependents] = useState<Dependent[]>([]);
  const [dependentsLoading, setDependentsLoading] = useState(false);
  const [selectedUserForDependents, setSelectedUserForDependents] = useState<User | null>(null);

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
    let filtered = users;

    if (searchTerm) {
      filtered = filtered.filter(user =>
        user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.cpf.includes(searchTerm.replace(/\D/g, '')) ||
        user.email?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedRole) {
      filtered = filtered.filter(user => user.roles.includes(selectedRole));
    }

    setFilteredUsers(filtered);
  }, [searchTerm, selectedRole, users]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Fetch users
      const usersResponse = await fetch(`${apiUrl}/api/users`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (usersResponse.ok) {
        const usersData = await usersResponse.json();
        setUsers(usersData);
      }

      // Fetch categories
      const categoriesResponse = await fetch(`${apiUrl}/api/service-categories`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (categoriesResponse.ok) {
        const categoriesData = await categoriesResponse.json();
        setCategories(categoriesData);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  const openCreateModal = () => {
    setModalMode('create');
    setFormData({
      name: '',
      cpf: '',
      email: '',
      phone: '',
      birth_date: '',
      address: '',
      address_number: '',
      address_complement: '',
      neighborhood: '',
      city: '',
      state: '',
      password: '',
      roles: [],
      category_id: '',
      professional_percentage: '50'
    });
    setSelectedUser(null);
    setIsModalOpen(true);
  };

  const openEditModal = (user: User) => {
    setModalMode('edit');
    setFormData({
      name: user.name,
      cpf: user.cpf,
      email: user.email || '',
      phone: user.phone || '',
      birth_date: user.birth_date || '',
      address: user.address || '',
      address_number: user.address_number || '',
      address_complement: user.address_complement || '',
      neighborhood: user.neighborhood || '',
      city: user.city || '',
      state: user.state || '',
      password: '',
      roles: user.roles || [],
      category_id: '',
      professional_percentage: user.professional_percentage?.toString() || '50'
    });
    setSelectedUser(user);
    setIsModalOpen(true);
  };

  const openActivationModal = (user: User) => {
    setUserToActivate(user);
    
    // Set default expiry to 1 year from now
    const defaultExpiry = new Date();
    defaultExpiry.setFullYear(defaultExpiry.getFullYear() + 1);
    setActivationExpiryDate(defaultExpiry.toISOString().split('T')[0]);
    
    setIsActivationModalOpen(true);
  };

  const openDependentsModal = async (user: User) => {
    setSelectedUserForDependents(user);
    setIsDependentsModalOpen(true);
    
    try {
      setDependentsLoading(true);
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/dependents/${user.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const dependentsData = await response.json();
        setSelectedUserDependents(dependentsData);
      } else {
        setSelectedUserDependents([]);
      }
    } catch (error) {
      console.error('Error fetching dependents:', error);
      setSelectedUserDependents([]);
    } finally {
      setDependentsLoading(false);
    }
  };

  const closeDependentsModal = () => {
    setIsDependentsModalOpen(false);
    setSelectedUserDependents([]);
    setSelectedUserForDependents(null);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setError('');
    setSuccess('');
  };

  const closeActivationModal = () => {
    setIsActivationModalOpen(false);
    setUserToActivate(null);
    setActivationExpiryDate('');
    setError('');
    setSuccess('');
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleRoleChange = (role: string, checked: boolean) => {
    setFormData(prev => ({
      ...prev,
      roles: checked 
        ? [...prev.roles, role]
        : prev.roles.filter(r => r !== role)
    }));
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    setFormData(prev => ({ ...prev, cpf: limitedValue }));
  };

  const formatPhone = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    setFormData(prev => ({ ...prev, phone: limitedValue }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validate professional fields
    if (formData.roles.includes('professional')) {
      if (!formData.category_id) {
        setError('Categoria é obrigatória para profissionais');
        return;
      }
      
      const percentage = parseInt(formData.professional_percentage);
      if (isNaN(percentage) || percentage < 0 || percentage > 100) {
        setError('Porcentagem deve ser um número entre 0 e 100');
        return;
      }
    }

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const url = modalMode === 'create' 
        ? `${apiUrl}/api/users`
        : `${apiUrl}/api/users/${selectedUser?.id}`;

      const method = modalMode === 'create' ? 'POST' : 'PUT';

      const submitData = {
        ...formData,
        cpf: formData.cpf.replace(/\D/g, ''),
        phone: formData.phone.replace(/\D/g, '') || null,
        email: formData.email.trim() || null,
        birth_date: formData.birth_date || null,
        address: formData.address.trim() || null,
        address_number: formData.address_number.trim() || null,
        address_complement: formData.address_complement.trim() || null,
        neighborhood: formData.neighborhood.trim() || null,
        city: formData.city.trim() || null,
        state: formData.state || null,
        category_id: formData.roles.includes('professional') && formData.category_id 
          ? parseInt(formData.category_id) 
          : null,
        professional_percentage: formData.roles.includes('professional') 
          ? parseInt(formData.professional_percentage) 
          : null
      };

      const response = await fetch(url, {
        method,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(submitData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao salvar usuário');
      }

      setSuccess(modalMode === 'create' ? 'Usuário criado com sucesso!' : 'Usuário atualizado com sucesso!');
      await fetchData();

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao salvar usuário');
    }
  };

  const handleActivateClient = async () => {
    if (!userToActivate || !activationExpiryDate) return;

    try {
      setIsActivating(true);
      setError('');
      setSuccess('');

      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      console.log('🔄 Activating client:', {
        user_id: userToActivate.id,
        expiry_date: activationExpiryDate,
        user_name: userToActivate.name
      });
      const response = await fetch(`${apiUrl}/api/admin/activate-client`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          user_id: userToActivate.id,
          expiry_date: activationExpiryDate
        })
      });

      console.log('📡 Activation response status:', response.status);
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao ativar cliente');
      }

      await fetchData();
      setSuccess('Cliente ativado com sucesso!');

      setTimeout(() => {
        closeActivationModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao ativar cliente');
    } finally {
      setIsActivating(false);
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
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error('❌ Activation error:', errorData);
        throw new Error(errorData.message || 'Erro ao excluir usuário');
      }

      const responseData = await response.json();
      console.log('✅ Client activated successfully:', responseData);
      await fetchData();
      setSuccess('Usuário excluído com sucesso!');
    } catch (error) {
      console.error('❌ Error in handleActivateClient:', error);
      setError(error instanceof Error ? error.message : 'Erro ao excluir usuário');
    } finally {
      setUserToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const formatCpfDisplay = (cpf: string) => {
    return cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4');
  };

  const formatPhoneDisplay = (phone: string) => {
    if (!phone) return '';
    const cleaned = phone.replace(/\D/g, '');
    if (cleaned.length === 11) {
      return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 7)}-${cleaned.slice(7)}`;
    } else if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 6)}-${cleaned.slice(6)}`;
    }
    return phone;
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return '';
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR');
  };

  const getSubscriptionStatusDisplay = (user: User) => {
    if (!user.roles.includes('client')) {
      return {
        text: 'N/A',
        className: 'bg-gray-100 text-gray-800',
        icon: null,
        showActivateButton: false
      };
    }

    switch (user.subscription_status) {
      case 'active':
        return {
          text: 'Ativo',
          className: 'bg-green-100 text-green-800',
          icon: <CheckCircle className="h-3 w-3 mr-1" />,
          showActivateButton: false
        };
      case 'pending':
        return {
          text: 'Pendente',
          className: 'bg-yellow-100 text-yellow-800',
          icon: <Clock className="h-3 w-3 mr-1" />,
          showActivateButton: true
        };
      case 'expired':
        return {
          text: 'Vencido',
          className: 'bg-red-100 text-red-800',
          icon: <AlertTriangle className="h-3 w-3 mr-1" />,
          showActivateButton: true
        };
      default:
        return {
          text: 'Inativo',
          className: 'bg-gray-100 text-gray-800',
          icon: <AlertTriangle className="h-3 w-3 mr-1" />,
          showActivateButton: true
        };
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

      {/* Filters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
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

        <select
          value={selectedRole}
          onChange={(e) => setSelectedRole(e.target.value)}
          className="input"
        >
          <option value="">Todas as funções</option>
          <option value="client">Clientes</option>
          <option value="professional">Profissionais</option>
          <option value="admin">Administradores</option>
        </select>
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
              {searchTerm || selectedRole ? 'Nenhum usuário encontrado' : 'Nenhum usuário cadastrado'}
            </h3>
            <p className="text-gray-600 mb-4">
              {searchTerm || selectedRole
                ? 'Tente ajustar os filtros de busca.'
                : 'Comece adicionando o primeiro usuário.'
              }
            </p>
            {!searchTerm && !selectedRole && (
              <button
                onClick={openCreateModal}
                className="btn btn-primary inline-flex items-center"
              >
                <UserPlus className="h-5 w-5 mr-2" />
                Adicionar Primeiro Usuário
              </button>
            )}
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
                    Status Convênio
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredUsers.map((user) => {
                  const statusInfo = getSubscriptionStatusDisplay(user);
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
                            <div className="text-sm text-gray-500">
                              CPF: {formatCpfDisplay(user.cpf)}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          {user.phone && (
                            <div className="flex items-center mb-1">
                              <Phone className="h-3 w-3 text-gray-400 mr-1" />
                              {formatPhoneDisplay(user.phone)}
                            </div>
                          )}
                          {user.email && (
                            <div className="flex items-center">
                              <Mail className="h-3 w-3 text-gray-400 mr-1" />
                              {user.email}
                            </div>
                          )}
                          {!user.phone && !user.email && (
                            <span className="text-gray-400 text-sm">Não informado</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          {user.address && (
                            <div className="flex items-start">
                              <MapPin className="h-3 w-3 text-gray-400 mr-1 mt-0.5" />
                              <div>
                                <div>
                                  {user.address}
                                  {user.address_number && `, ${user.address_number}`}
                                </div>
                                {user.city && user.state && (
                                  <div className="text-xs text-gray-500">
                                    {user.city}, {user.state}
                                  </div>
                                )}
                              </div>
                            </div>
                          )}
                          {!user.address && (
                            <span className="text-gray-400 text-sm">Não informado</span>
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
                              {role === 'admin' ? 'Admin' : role === 'professional' ? 'Profissional' : 'Cliente'}
                            </span>
                          ))}
                        </div>
                        {user.roles.includes('professional') && user.category_name && (
                          <div className="text-xs text-gray-500 mt-1">
                            {user.category_name} ({user.professional_percentage}%)
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full flex items-center w-fit ${statusInfo.className}`}>
                            {statusInfo.icon}
                            {statusInfo.text}
                          </span>
                          {user.subscription_expiry && user.subscription_status === 'active' && (
                            <div className="text-xs text-gray-500 mt-1">
                              Expira: {formatDate(user.subscription_expiry)}
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          {user.roles.includes('client') && (
                            <button
                              onClick={() => openDependentsModal(user)}
                              className="text-purple-600 hover:text-purple-900 flex items-center"
                              title="Ver Dependentes"
                            >
                              <Users className="h-4 w-4 mr-1" />
                              Dependentes
                            </button>
                          )}
                          {statusInfo.showActivateButton && (
                            <button
                              onClick={() => openActivationModal(user)}
                              className="text-green-600 hover:text-green-900 flex items-center"
                              title="Ativar Cliente"
                            >
                              <CheckCircle className="h-4 w-4 mr-1" />
                              Ativar
                            </button>
                          )}
                          <button
                            onClick={() => openEditModal(user)}
                            className="text-blue-600 hover:text-blue-900"
                            title="Editar"
                          >
                            <Edit className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => confirmDelete(user)}
                            className="text-red-600 hover:text-red-900"
                            title="Excluir"
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

      {/* User form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {modalMode === 'create' ? 'Novo Usuário' : 'Editar Usuário'}
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
              <div className="space-y-6">
                {/* Personal Information */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                    <User className="h-5 w-5 mr-2 text-red-600" />
                    Informações Pessoais
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Nome Completo *
                      </label>
                      <input
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleInputChange}
                        className="input"
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        CPF *
                      </label>
                      <input
                        type="text"
                        value={formData.cpf ? formatCpfDisplay(formData.cpf) : ''}
                        onChange={(e) => formatCpf(e.target.value)}
                        className="input"
                        placeholder="000.000.000-00"
                        disabled={modalMode === 'edit'}
                        required
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Email
                      </label>
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Telefone
                      </label>
                      <input
                        type="text"
                        value={formData.phone ? formatPhoneDisplay(formData.phone) : ''}
                        onChange={(e) => formatPhone(e.target.value)}
                        className="input"
                        placeholder="(00) 00000-0000"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Data de Nascimento
                      </label>
                      <input
                        type="date"
                        name="birth_date"
                        value={formData.birth_date}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    {modalMode === 'create' && (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Senha *
                        </label>
                        <div className="relative">
                          <input
                            type={showPassword ? "text" : "password"}
                            name="password"
                            value={formData.password}
                            onChange={handleInputChange}
                            className="input pr-10"
                            required
                          />
                          <button
                            type="button"
                            onClick={() => setShowPassword(!showPassword)}
                            className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                          >
                            {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Address Information */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
                    <MapPin className="h-5 w-5 mr-2 text-red-600" />
                    Endereço
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="md:col-span-2">
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Endereço
                      </label>
                      <input
                        type="text"
                        name="address"
                        value={formData.address}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Número
                      </label>
                      <input
                        type="text"
                        name="address_number"
                        value={formData.address_number}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Complemento
                      </label>
                      <input
                        type="text"
                        name="address_complement"
                        value={formData.address_complement}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Bairro
                      </label>
                      <input
                        type="text"
                        name="neighborhood"
                        value={formData.neighborhood}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Cidade
                      </label>
                      <input
                        type="text"
                        name="city"
                        value={formData.city}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Estado
                      </label>
                      <select
                        name="state"
                        value={formData.state}
                        onChange={handleInputChange}
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

                  <div className="space-y-3">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.roles.includes('client')}
                        onChange={(e) => handleRoleChange('client', e.target.checked)}
                        className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                      />
                      <span className="ml-2 text-sm text-gray-600">
                        Cliente - Pode agendar consultas e gerenciar dependentes
                      </span>
                    </label>

                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.roles.includes('professional')}
                        onChange={(e) => handleRoleChange('professional', e.target.checked)}
                        className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                      />
                      <span className="ml-2 text-sm text-gray-600">
                        Profissional - Pode registrar consultas e gerar relatórios
                      </span>
                    </label>

                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        checked={formData.roles.includes('admin')}
                        onChange={(e) => handleRoleChange('admin', e.target.checked)}
                        className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                      />
                      <span className="ml-2 text-sm text-gray-600">
                        Administrador - Acesso total ao sistema
                      </span>
                    </label>
                  </div>
                </div>

                {/* Professional specific fields */}
                {formData.roles.includes('professional') && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">
                      Configurações do Profissional
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Categoria *
                        </label>
                        <select
                          name="category_id"
                          value={formData.category_id}
                          onChange={handleInputChange}
                          className="input"
                          required={formData.roles.includes('professional')}
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
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Porcentagem do Profissional (%) *
                        </label>
                        <input
                          type="number"
                          name="professional_percentage"
                          value={formData.professional_percentage}
                          onChange={handleInputChange}
                          className="input"
                          min="0"
                          max="100"
                          required={formData.roles.includes('professional')}
                        />
                        <p className="text-xs text-gray-500 mt-1">
                          Porcentagem que o profissional recebe do valor das consultas do convênio
                        </p>
                      </div>
                    </div>

                    <div className="bg-blue-50 p-4 rounded-lg mt-4">
                      <h4 className="font-medium text-blue-900 mb-2">Como funciona a porcentagem:</h4>
                      <ul className="text-sm text-blue-700 space-y-1">
                        <li>• O profissional recebe a porcentagem definida do valor das consultas do convênio</li>
                        <li>• O restante fica para o convênio como taxa administrativa</li>
                        <li>• Consultas particulares: 100% para o profissional</li>
                        <li>• Exemplo: 70% = profissional recebe R$ 70 de uma consulta de R$ 100</li>
                      </ul>
                    </div>
                  </div>
                )}
              </div>

              <div className="flex justify-end space-x-3 mt-8 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {modalMode === 'create' ? 'Criar Usuário' : 'Salvar Alterações'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Client activation modal */}
      {isActivationModalOpen && userToActivate && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold flex items-center">
                <CheckCircle className="h-6 w-6 text-green-600 mr-2" />
                Ativar Cliente
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

            <div className="p-6">
              <div className="mb-4">
                <p className="text-gray-700 mb-2">
                  <span className="font-medium">Cliente:</span> {userToActivate.name}
                </p>
                <p className="text-gray-700 mb-4">
                  <span className="font-medium">CPF:</span> {formatCpfDisplay(userToActivate.cpf)}
                </p>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data de Encerramento do Convênio *
                  </label>
                  <input
                    type="date"
                    value={activationExpiryDate}
                    onChange={(e) => setActivationExpiryDate(e.target.value)}
                    className="input"
                    min={new Date().toISOString().split('T')[0]}
                    required
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    O convênio ficará ativo até a data selecionada (padrão: 1 ano)
                  </p>
                </div>
              </div>

              <div className="bg-green-50 p-4 rounded-lg mt-4">
                <h4 className="font-medium text-green-900 mb-2">O que acontece na ativação:</h4>
                <ul className="text-sm text-green-700 space-y-1">
                  <li>• Status do cliente muda para "Ativo"</li>
                  <li>• Cliente pode agendar consultas</li>
                  <li>• Cliente pode adicionar dependentes</li>
                  <li>• Acesso completo aos benefícios do convênio</li>
                </ul>
              </div>

              <div className="flex justify-end space-x-3 mt-6">
                <button
                  type="button"
                  onClick={closeActivationModal}
                  className="btn btn-secondary"
                  disabled={isActivating}
                >
                  Cancelar
                </button>
                <button
                  onClick={handleActivateClient}
                  className={`btn btn-primary flex items-center ${
                    isActivating ? 'opacity-70 cursor-not-allowed' : ''
                  }`}
                  disabled={isActivating || !activationExpiryDate}
                >
                  {isActivating ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Ativando...
                    </>
                  ) : (
                    <>
                      <CheckCircle className="h-5 w-5 mr-2" />
                      Ativar Cliente
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Dependents modal */}
      {isDependentsModalOpen && selectedUserForDependents && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-xl font-bold flex items-center">
                <Users className="h-6 w-6 text-purple-600 mr-2" />
                Dependentes de {selectedUserForDependents.name}
              </h2>
              <button
                onClick={closeDependentsModal}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="p-6">
              {dependentsLoading ? (
                <div className="text-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-600 mx-auto mb-4"></div>
                  <p className="text-gray-600">Carregando dependentes...</p>
                </div>
              ) : selectedUserDependents.length === 0 ? (
                <div className="text-center py-8 bg-gray-50 rounded-lg">
                  <Users className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 mb-2">
                    Nenhum dependente cadastrado
                  </h3>
                  <p className="text-gray-600">
                    Este cliente ainda não possui dependentes.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Nome
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          CPF
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Data de Nascimento
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Status
                        </th>
                        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                          Data de Cadastro
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white divide-y divide-gray-200">
                      {selectedUserDependents.map((dependent) => {
                        const depStatusInfo = getSubscriptionStatusDisplay({
                          ...dependent,
                          roles: ['client'],
                          subscription_status: dependent.subscription_status
                        } as User);
                        
                        return (
                          <tr key={dependent.id} className="hover:bg-gray-50">
                            <td className="px-4 py-4 whitespace-nowrap">
                              <div className="flex items-center">
                                <div className="flex-shrink-0 h-8 w-8">
                                  <div className="h-8 w-8 rounded-full bg-purple-100 flex items-center justify-center">
                                    <User className="h-4 w-4 text-purple-600" />
                                  </div>
                                </div>
                                <div className="ml-3">
                                  <div className="text-sm font-medium text-gray-900">
                                    {dependent.name}
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-900">
                              {formatCpfDisplay(dependent.cpf)}
                            </td>
                            <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
                              {formatDate(dependent.birth_date)}
                            </td>
                            <td className="px-4 py-4 whitespace-nowrap">
                              <span className={`px-2 py-1 text-xs font-medium rounded-full flex items-center w-fit ${depStatusInfo.className}`}>
                                {depStatusInfo.icon}
                                {depStatusInfo.text}
                              </span>
                              {dependent.subscription_expiry && dependent.subscription_status === 'active' && (
                                <div className="text-xs text-gray-500 mt-1">
                                  Expira: {formatDate(dependent.subscription_expiry)}
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
                              {formatDate(dependent.created_at)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Summary */}
              {selectedUserDependents.length > 0 && (
                <div className="mt-6 p-4 bg-purple-50 rounded-lg border border-purple-200">
                  <h4 className="font-medium text-purple-900 mb-2">Resumo dos Dependentes</h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div className="text-center">
                      <div className="text-lg font-bold text-green-600">
                        {selectedUserDependents.filter(d => d.subscription_status === 'active').length}
                      </div>
                      <div className="text-green-700">Ativos</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-bold text-yellow-600">
                        {selectedUserDependents.filter(d => d.subscription_status === 'pending').length}
                      </div>
                      <div className="text-yellow-700">Pendentes</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-bold text-red-600">
                        {selectedUserDependents.filter(d => d.subscription_status === 'expired').length}
                      </div>
                      <div className="text-red-700">Vencidos</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-bold text-purple-600">
                        {selectedUserDependents.length}
                      </div>
                      <div className="text-purple-700">Total</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && userToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir o usuário <strong>{userToDelete.name}</strong>?
              Esta ação não pode ser desfeita.
            </p>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelDelete}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={deleteUser}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Check className="h-4 w-4 mr-2" />
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