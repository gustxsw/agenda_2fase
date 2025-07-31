import React, { useState, useEffect } from 'react';
import { FilePlus, Edit, Trash2, FileText, Check, X, FolderPlus } from 'lucide-react';

type Service = {
  id: number;
  name: string;
  description: string;
  base_price: number;
  category_id: number | null;
  category_name: string | null;
  is_base_service: boolean;
};

type Category = {
  id: number;
  name: string;
  description: string;
};

const ManageServicesPage: React.FC = () => {
  const [services, setServices] = useState<Service[]>([]);
  const [categories, setCategories] = useState<Category[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<'create' | 'edit'>('create');
  const [selectedService, setSelectedService] = useState<Service | null>(null);
  
  // Category modal state
  const [isCategoryModalOpen, setIsCategoryModalOpen] = useState(false);
  
  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [basePrice, setBasePrice] = useState('');
  const [categoryId, setCategoryId] = useState<string>('');
  const [isBaseService, setIsBaseService] = useState(false);
  
  // Category form state
  const [categoryName, setCategoryName] = useState('');
  const [categoryDescription, setCategoryDescription] = useState('');
  
  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [serviceToDelete, setServiceToDelete] = useState<Service | null>(null);

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
  
  useEffect(() => {
    fetchData();
  }, []);
  
  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      console.log('Fetching services data from:', apiUrl);
      
      // Fetch categories
      const categoriesResponse = await fetch(`${apiUrl}/api/service-categories`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!categoriesResponse.ok) {
        throw new Error('Falha ao carregar categorias');
      }
      
      const categoriesData = await categoriesResponse.json();
      setCategories(categoriesData);
      
      // Fetch services
      const servicesResponse = await fetch(`${apiUrl}/api/services`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!servicesResponse.ok) {
        throw new Error('Falha ao carregar serviços');
      }
      
      const servicesData = await servicesResponse.json();
      setServices(servicesData);
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };
  
  const openCreateModal = () => {
    setModalMode('create');
    setName('');
    setDescription('');
    setBasePrice('');
    setCategoryId('');
    setIsBaseService(false);
    setSelectedService(null);
    setIsModalOpen(true);
  };
  
  const openEditModal = (service: Service) => {
    setModalMode('edit');
    setName(service.name);
    setDescription(service.description);
    setBasePrice(service.base_price.toString());
    setCategoryId(service.category_id?.toString() || '');
    setIsBaseService(service.is_base_service);
    setSelectedService(service);
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
      
      // Validate base price
      const priceValue = parseFloat(basePrice);
      if (isNaN(priceValue) || priceValue <= 0) {
        setError('O preço base deve ser um valor numérico maior que zero');
        return;
      }
      
      const serviceData = {
        name,
        description,
        base_price: priceValue,
        category_id: categoryId ? parseInt(categoryId) : null,
        is_base_service: isBaseService,
      };
      
      if (modalMode === 'create') {
        // Create service
        const response = await fetch(`${apiUrl}/api/services`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(serviceData),
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao criar serviço');
        }
        
        setSuccess('Serviço criado com sucesso!');
      } else if (modalMode === 'edit' && selectedService) {
        // Update service
        const response = await fetch(`${apiUrl}/api/services/${selectedService.id}`, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(serviceData),
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Falha ao atualizar serviço');
        }
        
        setSuccess('Serviço atualizado com sucesso!');
      }
      
      // Refresh services list
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
  
  const handleCategorySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/service-categories`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: categoryName,
          description: categoryDescription,
        }),
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao criar categoria');
      }
      
      // Refresh data
      await fetchData();
      
      setSuccess('Categoria criada com sucesso!');
      
      // Close modal after short delay
      setTimeout(() => {
        setIsCategoryModalOpen(false);
        setCategoryName('');
        setCategoryDescription('');
      }, 1500);
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Ocorreu um erro ao criar a categoria');
      }
    }
  };
  
  const confirmDelete = (service: Service) => {
    setServiceToDelete(service);
    setShowDeleteConfirm(true);
  };
  
  const cancelDelete = () => {
    setServiceToDelete(null);
    setShowDeleteConfirm(false);
  };
  
  const deleteService = async () => {
    if (!serviceToDelete) return;
    
    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();
      
      const response = await fetch(`${apiUrl}/api/services/${serviceToDelete.id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Falha ao excluir serviço');
      }
      
      // Refresh services list
      await fetchData();
      
      setSuccess('Serviço excluído com sucesso!');
    } catch (error) {
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError('Ocorreu um erro ao excluir o serviço');
      }
    } finally {
      setServiceToDelete(null);
      setShowDeleteConfirm(false);
    }
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
          <h1 className="text-2xl font-bold text-gray-900">Gerenciar Serviços</h1>
          <p className="text-gray-600">Adicione, edite ou remova serviços do sistema</p>
        </div>
        
        <div className="flex space-x-2">
          <button
            onClick={() => setIsCategoryModalOpen(true)}
            className="btn btn-outline flex items-center"
          >
            <FolderPlus className="h-5 w-5 mr-2" />
            Nova Categoria
          </button>
          
          <button
            onClick={openCreateModal}
            className="btn btn-primary flex items-center"
          >
            <FilePlus className="h-5 w-5 mr-2" />
            Novo Serviço
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
            <p className="text-gray-600">Carregando serviços...</p>
          </div>
        ) : services.length === 0 ? (
          <div className="text-center py-8 bg-gray-50 rounded-lg">
            <p className="text-gray-600">Nenhum serviço encontrado.</p>
            <button
              onClick={openCreateModal}
              className="btn btn-primary mt-4 inline-flex items-center"
            >
              <FilePlus className="h-5 w-5 mr-2" />
              Adicionar Serviço
            </button>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Nome</th>
                  <th>Categoria</th>
                  <th>Descrição</th>
                  <th>Preço Base</th>
                  <th>Tipo</th>
                  <th>Ações</th>
                </tr>
              </thead>
              <tbody>
                {services.map((service) => (
                  <tr key={service.id}>
                    <td className="flex items-center">
                      <FileText className="h-5 w-5 mr-2 text-gray-500" />
                      {service.name}
                    </td>
                    <td>{service.category_name || 'Sem categoria'}</td>
                    <td>{service.description}</td>
                    <td>{formatCurrency(service.base_price)}</td>
                    <td>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        service.is_base_service
                          ? 'bg-blue-100 text-blue-800'
                          : 'bg-gray-100 text-gray-800'
                      }`}>
                        {service.is_base_service ? 'Base' : 'Específico'}
                      </span>
                    </td>
                    <td>
                      <div className="flex space-x-2">
                        <button
                          onClick={() => openEditModal(service)}
                          className="p-1 text-blue-600 hover:text-blue-800"
                          title="Editar"
                        >
                          <Edit className="h-5 w-5" />
                        </button>
                        <button
                          onClick={() => confirmDelete(service)}
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
      
      {/* Service form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">
                {modalMode === 'create' ? 'Adicionar Serviço' : 'Editar Serviço'}
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
                  Nome do Serviço
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
              
              <div className="mb-4">
                <label htmlFor="category" className="block text-sm font-medium text-gray-700 mb-1">
                  Categoria
                </label>
                <select
                  id="category"
                  value={categoryId}
                  onChange={(e) => setCategoryId(e.target.value)}
                  className="input"
                >
                  <option value="">Selecione uma categoria</option>
                  {categories.map((category) => (
                    <option key={category.id} value={category.id}>
                      {category.name}
                    </option>
                  ))}
                </select>
              </div>
              
              <div className="mb-4">
                <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">
                  Descrição
                </label>
                <textarea
                  id="description"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="input min-h-[100px]"
                  required
                />
              </div>
              
              <div className="mb-4">
                <label htmlFor="basePrice" className="block text-sm font-medium text-gray-700 mb-1">
                  Preço Base (R$)
                </label>
                <input
                  id="basePrice"
                  type="number"
                  min="0"
                  step="0.01"
                  value={basePrice}
                  onChange={(e) => setBasePrice(e.target.value)}
                  className="input"
                  required
                />
              </div>
              
              <div className="mb-6">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={isBaseService}
                    onChange={(e) => setIsBaseService(e.target.checked)}
                    className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                  />
                  <span className="ml-2 text-sm text-gray-600">
                    Este é um serviço base da categoria
                  </span>
                </label>
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
      
      {/* Category form modal */}
      {isCategoryModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">Nova Categoria de Serviço</h2>
              <button
                onClick={() => setIsCategoryModalOpen(false)}
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
            
            <form onSubmit={handleCategorySubmit}>
              <div className="mb-4">
                <label htmlFor="categoryName" className="block text-sm font-medium text-gray-700 mb-1">
                  Nome da Categoria
                </label>
                <input
                  id="categoryName"
                  type="text"
                  value={categoryName}
                  onChange={(e) => setCategoryName(e.target.value)}
                  className="input"
                  required
                />
              </div>
              
              <div className="mb-6">
                <label htmlFor="categoryDescription" className="block text-sm font-medium text-gray-700 mb-1">
                  Descrição
                </label>
                <textarea
                  id="categoryDescription"
                  value={categoryDescription}
                  onChange={(e) => setCategoryDescription(e.target.value)}
                  className="input min-h-[100px]"
                  required
                />
              </div>
              
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={() => setIsCategoryModalOpen(false)}
                  className="btn btn-secondary mr-2"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  Criar Categoria
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      
      {/* Delete confirmation modal */}
      {showDeleteConfirm && serviceToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir o serviço <strong>{serviceToDelete.name}</strong>?
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
                onClick={deleteService}
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

export default ManageServicesPage;