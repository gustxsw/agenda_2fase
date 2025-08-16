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
                  </div>
                ) : (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Fazer Upload da Assinatura
                    </label>
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
                  </div>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    CEP
                  </label>
                  <input
                    type="text"
                    value={locationData.zip_code}
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
                    value={locationData.phone}
                    onChange={(e) => setLocationData(prev => ({ ...prev, phone: formatPhone(e.target.value) }))}
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