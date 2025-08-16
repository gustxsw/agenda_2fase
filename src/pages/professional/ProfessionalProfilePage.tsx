import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { 
  Settings, 
  MapPin, 
  Plus, 
  Edit, 
  Trash2, 
  Check, 
  X, 
  Upload, 
  Camera,
  FileImage,
  User
} from 'lucide-react';

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  address_number: string;
  address_complement: string;
  neighborhood: string;
  city: string;
  state: string;
  zip_code: string;
  phone: string;
  is_default: boolean;
};

const ProfessionalProfilePage: React.FC = () => {
  const { user } = useAuth();
  const [locations, setLocations] = useState<AttendanceLocation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Photo upload state
  const [photoUrl, setPhotoUrl] = useState<string | null>(null);
  const [isUploadingPhoto, setIsUploadingPhoto] = useState(false);
  const [photoError, setPhotoError] = useState('');
  const [photoSuccess, setPhotoSuccess] = useState('');
  
  // Signature upload state
  const [signatureUrl, setSignatureUrl] = useState<string | null>(null);
  const [isUploadingSignature, setIsUploadingSignature] = useState(false);
  const [signatureError, setSignatureError] = useState('');
  const [signatureSuccess, setSignatureSuccess] = useState('');
  
  // Location modal state
  const [isLocationModalOpen, setIsLocationModalOpen] = useState(false);
  const [locationModalMode, setLocationModalMode] = useState<'create' | 'edit'>('create');
  const [selectedLocation, setSelectedLocation] = useState<AttendanceLocation | null>(null);
  
  // Location form state
  const [locationData, setLocationData] = useState({
    name: '',
    address: '',
    address_number: '',
    address_complement: '',
    neighborhood: '',
    city: '',
    state: '',
    zip_code: '',
    phone: '',
    is_default: false
  });
  
  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [locationToDelete, setLocationToDelete] = useState<AttendanceLocation | null>(null);

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

      // Fetch user data to get photo and signature URLs
      const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setPhotoUrl(userData.photo_url);
        setSignatureUrl(userData.signature_url);
      }

      // Fetch attendance locations
      const locationsResponse = await fetch(`${apiUrl}/api/attendance-locations`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        setLocations(locationsData);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePhotoUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setPhotoError('Por favor, selecione apenas arquivos de imagem');
      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      setPhotoError('A imagem deve ter no máximo 5MB');
      return;
    }

    try {
      setIsUploadingPhoto(true);
      setPhotoError('');
      setPhotoSuccess('');

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
      setPhotoSuccess('Foto atualizada com sucesso!');

      setTimeout(() => {
        setPhotoSuccess('');
      }, 3000);

    } catch (error) {
      console.error('Error uploading photo:', error);
      setPhotoError(error instanceof Error ? error.message : 'Erro ao fazer upload da foto');
    } finally {
      setIsUploadingPhoto(false);
    }
  };

  const handleSignatureUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    console.log('🔄 Starting signature upload:', file.name, file.type, file.size);

    if (!file.type.startsWith('image/')) {
      setSignatureError('Por favor, selecione apenas arquivos de imagem');
      return;
    }

    if (file.size > 2 * 1024 * 1024) {
      setSignatureError('A imagem deve ter no máximo 2MB');
      return;
    }

    try {
      setIsUploadingSignature(true);
      setSignatureError('');
      setSignatureSuccess('');

      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      console.log('🔄 Making signature upload request to:', `${apiUrl}/api/upload-signature`);

      const formData = new FormData();
      formData.append('signature', file);

      console.log('🔄 FormData created with signature field');

      const response = await fetch(`${apiUrl}/api/upload-signature`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          // Note: Don't set Content-Type for FormData, let browser set it with boundary
        },
        body: formData,
      });

      console.log('📡 Signature upload response status:', response.status);
      console.log('📡 Signature upload response headers:', Object.fromEntries(response.headers.entries()));

      if (!response.ok) {
        const responseText = await response.text();
        console.error('❌ Signature upload error response:', responseText);
        
        let errorData;
        try {
          errorData = JSON.parse(responseText);
        } catch (parseError) {
          console.error('❌ Failed to parse error response as JSON:', parseError);
          throw new Error(`Erro do servidor (${response.status}): ${responseText.substring(0, 100)}`);
        }
        
        throw new Error(errorData.message || 'Falha ao fazer upload da assinatura');
      }

      const data = await response.json();
      console.log('✅ Signature upload successful:', data);
      
      setSignatureUrl(data.signatureUrl);
      setSignatureSuccess('Assinatura atualizada com sucesso!');

      setTimeout(() => {
        setSignatureSuccess('');
      }, 3000);

    } catch (error) {
      console.error('Error uploading signature:', error);
      setSignatureError(error instanceof Error ? error.message : 'Erro ao fazer upload da assinatura');
    } finally {
      setIsUploadingSignature(false);
    }
  };

  const openCreateLocationModal = () => {
    setLocationModalMode('create');
    setLocationData({
      name: '',
      address: '',
      address_number: '',
      address_complement: '',
      neighborhood: '',
      city: '',
      state: '',
      zip_code: '',
      phone: '',
      is_default: locations.length === 0
    });
    setSelectedLocation(null);
    setIsLocationModalOpen(true);
  };

  const openEditLocationModal = (location: AttendanceLocation) => {
    setLocationModalMode('edit');
    setLocationData({
      name: location.name,
      address: location.address,
      address_number: location.address_number || '',
      address_complement: location.address_complement || '',
      neighborhood: location.neighborhood || '',
      city: location.city || '',
      state: location.state || '',
      zip_code: location.zip_code || '',
      phone: location.phone || '',
      is_default: location.is_default
    });
    setSelectedLocation(location);
    setIsLocationModalOpen(true);
  };

  const closeLocationModal = () => {
    setIsLocationModalOpen(false);
    setError('');
    setSuccess('');
  };

  const handleLocationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const url = locationModalMode === 'create' 
        ? `${apiUrl}/api/attendance-locations`
        : `${apiUrl}/api/attendance-locations/${selectedLocation?.id}`;

      const method = locationModalMode === 'create' ? 'POST' : 'PUT';

      const response = await fetch(url, {
        method,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(locationData)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao salvar local');
      }

      setSuccess(locationModalMode === 'create' ? 'Local criado com sucesso!' : 'Local atualizado com sucesso!');
      await fetchData();

      setTimeout(() => {
        closeLocationModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao salvar local');
    }
  };

  const confirmDeleteLocation = (location: AttendanceLocation) => {
    setLocationToDelete(location);
    setShowDeleteConfirm(true);
  };

  const cancelDeleteLocation = () => {
    setLocationToDelete(null);
    setShowDeleteConfirm(false);
  };

  const deleteLocation = async () => {
    if (!locationToDelete) return;

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/attendance-locations/${locationToDelete.id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Erro ao excluir local');
      }

      await fetchData();
      setSuccess('Local excluído com sucesso!');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Erro ao excluir local');
    } finally {
      setLocationToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const formatPhone = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 11);
    
    if (limitedValue.length <= 2) {
      return limitedValue;
    } else if (limitedValue.length <= 7) {
      return `(${limitedValue.slice(0, 2)}) ${limitedValue.slice(2)}`;
    } else {
      return `(${limitedValue.slice(0, 2)}) ${limitedValue.slice(2, 7)}-${limitedValue.slice(7)}`;
    }
  };

  const formatZipCode = (value: string) => {
    const numericValue = value.replace(/\D/g, '');
    const limitedValue = numericValue.slice(0, 8);
    
    if (limitedValue.length <= 5) {
      return limitedValue;
    } else {
      return `${limitedValue.slice(0, 5)}-${limitedValue.slice(5)}`;
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Perfil Profissional</h1>
        <p className="text-gray-600">Gerencie suas informações e locais de atendimento</p>
      </div>

      {/* Photo upload feedback */}
      {photoError && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
          {photoError}
        </div>
      )}

      {photoSuccess && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6">
          {photoSuccess}
        </div>
      )}

      {/* Signature upload feedback */}
      {signatureError && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
          {signatureError}
        </div>
      )}

      {signatureSuccess && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6">
          {signatureSuccess}
        </div>
      )}

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

      {/* Profile Information */}
      <div className="card mb-6">
        <div className="flex items-center mb-6">
          <User className="h-6 w-6 text-red-600 mr-2" />
          <h2 className="text-xl font-semibold">Informações do Perfil</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Photo Upload */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Foto do Perfil
            </label>
            {photoUrl ? (
              <div className="relative">
                <img
                  src={photoUrl}
                  alt="Foto do perfil"
                  className="w-32 h-32 rounded-full object-cover border-4 border-red-100"
                />
                <label className="absolute bottom-0 right-0 bg-red-600 text-white rounded-full p-2 cursor-pointer hover:bg-red-700 transition-colors">
                  <Camera className="h-4 w-4" />
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
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                  </div>
                )}
              </div>
            ) : (
              <div className="w-32 h-32 bg-gray-100 rounded-full flex items-center justify-center border-2 border-dashed border-gray-300">
                <label className="cursor-pointer text-center">
                  <Camera className="h-8 w-8 text-gray-400 mx-auto mb-2" />
                  <span className="text-sm text-gray-500">Adicionar foto</span>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handlePhotoUpload}
                    className="hidden"
                    disabled={isUploadingPhoto}
                  />
                </label>
                {isUploadingPhoto && (
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-red-600"></div>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Signature Upload */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Assinatura Digital
            </label>
            {signatureUrl ? (
              <div className="relative">
                <img
                  src={signatureUrl}
                  alt="Assinatura digital"
                  className="w-48 h-24 object-contain border-2 border-gray-200 rounded-lg bg-white p-2"
                />
                <div className="mt-2 flex items-center space-x-2">
                  <label className="btn btn-secondary cursor-pointer inline-flex items-center">
                    <Upload className="h-4 w-4 mr-2" />
                    Alterar Assinatura
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleSignatureUpload}
                      className="hidden"
                      disabled={isUploadingSignature}
                    />
                  </label>
                  {isUploadingSignature && (
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-red-600"></div>
                  )}
                </div>
              </div>
            ) : (
              <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-red-400 transition-colors">
                <FileImage className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                <div className="space-y-2">
                  <label className="btn btn-primary cursor-pointer inline-flex items-center">
                    <Upload className="h-4 w-4 mr-2" />
                    {isUploadingSignature ? 'Enviando...' : 'Escolher Imagem'}
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleSignatureUpload}
                      className="hidden"
                      disabled={isUploadingSignature}
                    />
                  </label>
                  {isUploadingSignature && (
                    <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-red-600 mx-auto mt-2"></div>
                  )}
                </div>
                <p className="text-sm text-gray-500 mt-2">
                  PNG, JPG ou JPEG até 2MB
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Attendance Locations */}
      <div className="card">
        <div className="flex justify-between items-center mb-6">
          <div className="flex items-center">
            <MapPin className="h-6 w-6 text-red-600 mr-2" />
            <h2 className="text-xl font-semibold">Locais de Atendimento</h2>
          </div>
          
          <button
            onClick={openCreateLocationModal}
            className="btn btn-primary flex items-center"
          >
            <Plus className="h-5 w-5 mr-2" />
            Novo Local
          </button>
        </div>

        {isLoading ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando locais...</p>
          </div>
        ) : locations.length === 0 ? (
          <div className="text-center py-8 bg-gray-50 rounded-lg">
            <MapPin className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              Nenhum local cadastrado
            </h3>
            <p className="text-gray-600 mb-4">
              Configure seus locais de atendimento para facilitar o agendamento.
            </p>
            <button
              onClick={openCreateLocationModal}
              className="btn btn-primary inline-flex items-center"
            >
              <Plus className="h-5 w-5 mr-2" />
              Adicionar Primeiro Local
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {locations.map((location) => (
              <div
                key={location.id}
                className={`p-4 rounded-lg border-2 transition-colors ${
                  location.is_default
                    ? 'border-red-200 bg-red-50'
                    : 'border-gray-200 bg-white hover:bg-gray-50'
                }`}
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center mb-2">
                      <h3 className="text-lg font-semibold text-gray-900">
                        {location.name}
                      </h3>
                      {location.is_default && (
                        <span className="ml-2 px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-medium">
                          Padrão
                        </span>
                      )}
                    </div>
                    
                    <div className="space-y-1 text-sm text-gray-600">
                      {location.address && (
                        <p>
                          {location.address}
                          {location.address_number && `, ${location.address_number}`}
                          {location.address_complement && `, ${location.address_complement}`}
                        </p>
                      )}
                      {(location.neighborhood || location.city || location.state) && (
                        <p>
                          {[location.neighborhood, location.city, location.state]
                            .filter(Boolean)
                            .join(', ')}
                        </p>
                      )}
                      {location.zip_code && (
                        <p>CEP: {formatZipCode(location.zip_code)}</p>
                      )}
                      {location.phone && (
                        <p>Telefone: {formatPhone(location.phone)}</p>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2 ml-4">
                    <button
                      onClick={() => openEditLocationModal(location)}
                      className="p-2 text-blue-600 hover:text-blue-800 hover:bg-blue-50 rounded-lg transition-colors"
                      title="Editar"
                    >
                      <Edit className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => confirmDeleteLocation(location)}
                      className="p-2 text-red-600 hover:text-red-800 hover:bg-red-50 rounded-lg transition-colors"
                      title="Excluir"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Location form modal */}
      {isLocationModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {locationModalMode === 'create' ? 'Novo Local de Atendimento' : 'Editar Local de Atendimento'}
              </h2>
            </div>

            <form onSubmit={handleLocationSubmit} className="p-6">
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nome do Local *
                  </label>
                  <input
                    type="text"
                    value={locationData.name}
                    onChange={(e) => setLocationData(prev => ({ ...prev, name: e.target.value }))}
                    className="input"
                    placeholder="Ex: Clínica Principal, Consultório Centro"
                    required
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      CEP
                    </label>
                    <input
                      type="text"
                      value={formatZipCode(locationData.zip_code)}
                      onChange={(e) => setLocationData(prev => ({ ...prev, zip_code: e.target.value.replace(/\D/g, '').slice(0, 8) }))}
                      className="input"
                      placeholder="00000-000"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Endereço
                    </label>
                    <input
                      type="text"
                      value={locationData.address}
                      onChange={(e) => setLocationData(prev => ({ ...prev, address: e.target.value }))}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Número
                    </label>
                    <input
                      type="text"
                      value={locationData.address_number}
                      onChange={(e) => setLocationData(prev => ({ ...prev, address_number: e.target.value }))}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Complemento
                    </label>
                    <input
                      type="text"
                      value={locationData.address_complement}
                      onChange={(e) => setLocationData(prev => ({ ...prev, address_complement: e.target.value }))}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Bairro
                    </label>
                    <input
                      type="text"
                      value={locationData.neighborhood}
                      onChange={(e) => setLocationData(prev => ({ ...prev, neighborhood: e.target.value }))}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Cidade
                    </label>
                    <input
                      type="text"
                      value={locationData.city}
                      onChange={(e) => setLocationData(prev => ({ ...prev, city: e.target.value }))}
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Estado
                    </label>
                    <select
                      value={locationData.state}
                      onChange={(e) => setLocationData(prev => ({ ...prev, state: e.target.value }))}
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

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Telefone
                    </label>
                    <input
                      type="text"
                      value={formatPhone(locationData.phone)}
                      onChange={(e) => setLocationData(prev => ({ ...prev, phone: e.target.value.replace(/\D/g, '') }))}
                      className="input"
                      placeholder="(00) 00000-0000"
                    />
                  </div>
                </div>

                <div>
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={locationData.is_default}
                      onChange={(e) => setLocationData(prev => ({ ...prev, is_default: e.target.checked }))}
                      className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                    />
                    <span className="ml-2 text-sm text-gray-600">
                      Definir como local padrão
                    </span>
                  </label>
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeLocationModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {locationModalMode === 'create' ? 'Criar Local' : 'Salvar Alterações'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && locationToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>
            
            <p className="mb-6">
              Tem certeza que deseja excluir o local <strong>{locationToDelete.name}</strong>?
              Esta ação não pode ser desfeita.
            </p>
            
            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelDeleteLocation}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={deleteLocation}
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

export default ProfessionalProfilePage;