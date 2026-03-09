'use client'

import { useState, useEffect } from 'react'
import { Camera } from '../../services/cameraService'

interface EditingCamera extends Camera {
  isEditing: boolean
}

const CAMERA_MODELS = {
  'Hikvision': [
    'DS-2CD2085FWD-I',
    'DS-2CD2143G0-I',
    'DS-2DE3304W-DE',
    'DS-2CD2347G2-LU'
  ],
  'Dahua': [
    'IPC-HDBW4431R-ZS',
    'IPC-HFW5241E-ZE',
    'SD49225T-HN',
    'IPC-HDBW2431E-S'
  ],
  'Axis': [
    'M3045-V',
    'P3245-LVE',
    'Q6075-E',
    'M1135'
  ],
  'Amcrest': [
    'IP8M-2496EB',
    'IP5M-T1179EW',
    'IP4M-1051B'
  ],
  'Reolink': [
    'RLC-810A',
    'RLC-520',
    'Lumus',
    'E1 Zoom'
  ],
  'Bosch': [
    'DINION IP 5000',
    'AUTODOME IP 5000i',
    'FLEXIDOME IP starlight 8000i'
  ]
}

export default function CamerasPage() {
  const [cameras, setCameras] = useState<EditingCamera[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [deleteModal, setDeleteModal] = useState<{ isOpen: boolean; camera?: Camera }>({ isOpen: false })
  const [newCamera, setNewCamera] = useState({
    name: '',
    vendor: '',
    product: '',
    criticity: 'medium' as const
  })
  const [isAddingCamera, setIsAddingCamera] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [criticityFilter, setCriticityFilter] = useState('all')
  const [syncingCameras, setSyncingCameras] = useState<Set<number>>(new Set())

  useEffect(() => {
    fetchCameras()
  }, [])

  const fetchCameras = async () => {
    try {
      const response = await fetch('/api/cameras')
      const data = await response.json()
      
      if (data.success) {
        setCameras(data.cameras.map((camera: Camera) => ({ ...camera, isEditing: false })))
        
        // Trigger vulnerability sync for all cameras on first load
        const cameraIds = data.cameras.map((c: Camera) => c.id)
        if (cameraIds.length > 0) {
          triggerVulnerabilitySync(cameraIds)
        }
      }
    } catch (error) {
      console.error('Error fetching cameras:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const triggerVulnerabilitySync = async (cameraIds: number[]) => {
    try {
      // Mark cameras as syncing
      setSyncingCameras(prev => {
        const merged = new Set<number>()
        prev.forEach(id => merged.add(id))
        cameraIds.forEach(id => merged.add(id))
        return merged
      })

      const response = await fetch('http://localhost:8000/api/v1/sync', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          camera_ids: cameraIds,
          max_results: 100
        }),
        signal: AbortSignal.timeout(30000)
      })

      if (!response.ok) {
        console.warn('Vulnerability sync failed:', response.status)
        // Mark cameras as failed
        setCameras(prev => prev.map(camera => 
          cameraIds.includes(camera.id) 
            ? { ...camera, sync_status: 'failed' as const }
            : camera
        ))
      } else {
        console.log('Vulnerability sync completed for cameras:', cameraIds)
        // Mark cameras as completed
        setCameras(prev => prev.map(camera => 
          cameraIds.includes(camera.id) 
            ? { ...camera, sync_status: 'completed' as const }
            : camera
        ))
      }
    } catch (error) {
      console.warn('Failed to trigger vulnerability sync:', error)
      // Mark cameras as failed
      setCameras(prev => prev.map(camera => 
        cameraIds.includes(camera.id) 
          ? { ...camera, sync_status: 'failed' as const }
          : camera
      ))
    } finally {
      // Remove from syncing set
      setSyncingCameras(prev => {
        const newSet = new Set(prev)
        cameraIds.forEach(id => newSet.delete(id))
        return newSet
      })
    }
  }

  const handleEdit = (cameraId: number) => {
    setCameras(prev => prev.map(camera => 
      camera.id === cameraId 
        ? { ...camera, isEditing: true }
        : { ...camera, isEditing: false }
    ))
  }

  const handleCancelEdit = (cameraId: number) => {
    setCameras(prev => prev.map(camera => 
      camera.id === cameraId 
        ? { ...camera, isEditing: false }
        : camera
    ))
    fetchCameras() // Reset to original values
  }

  const handleSaveEdit = async (camera: EditingCamera) => {
    try {
      const response = await fetch(`/api/cameras/${camera.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: camera.name,
          vendor: camera.vendor,
          product: camera.product,
          criticity: camera.criticity
        }),
      })

      if (response.ok) {
        setCameras(prev => prev.map(c => 
          c.id === camera.id 
            ? { ...camera, isEditing: false }
            : c
        ))
      }
    } catch (error) {
      console.error('Error updating camera:', error)
    }
  }

  const handleDelete = async (camera: Camera) => {
    try {
      const response = await fetch(`/api/cameras/${camera.id}`, {
        method: 'DELETE',
      })

      if (response.ok) {
        setCameras(prev => prev.filter(c => c.id !== camera.id))
        setDeleteModal({ isOpen: false })
      }
    } catch (error) {
      console.error('Error deleting camera:', error)
    }
  }

  const handleAddCamera = async () => {
    if (!newCamera.name || !newCamera.vendor || !newCamera.product) return

    try {
      const response = await fetch('/api/cameras', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newCamera),
      })

      const data = await response.json()

      if (data.success) {
        setCameras(prev => [{ ...data.camera, isEditing: false }, ...prev])
        setNewCamera({ name: '', vendor: '', product: '', criticity: 'medium' })
        setIsAddingCamera(false)
      }
    } catch (error) {
      console.error('Error adding camera:', error)
    }
  }

  const getCriticityColor = (criticity: string) => {
    switch (criticity) {
      case 'critical': return 'text-red-400'
      case 'high': return 'text-orange-400'
      case 'medium': return 'text-yellow-400'
      case 'low': return 'text-green-400'
      default: return 'text-gray-400'
    }
  }

  const getCriticityBg = (criticity: string) => {
    switch (criticity) {
      case 'critical': return 'bg-red-500/20 border-red-500'
      case 'high': return 'bg-orange-500/20 border-orange-500'
      case 'medium': return 'bg-yellow-500/20 border-yellow-500'
      case 'low': return 'bg-green-500/20 border-green-500'
      default: return 'bg-gray-500/20 border-gray-500'
    }
  }

  const getSyncStatusDisplay = (camera: EditingCamera) => {
    if (syncingCameras.has(camera.id)) {
      return (
        <div className="flex items-center text-yellow-400">
          <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-yellow-400 mr-2"></div>
          Synchronisation...
        </div>
      )
    }

    switch (camera.sync_status) {
      case 'completed':
        return <span className="text-green-400">✓ Synchronisé</span>
      case 'failed':
        return <span className="text-red-400">✗ Échec</span>
      default:
        return <span className="text-gray-400">Non synchronisé</span>
    }
  }

  const filteredCameras = cameras.filter((camera) => {
    const normalizedSearch = searchTerm.trim().toLowerCase()
    const matchesSearch =
      normalizedSearch.length === 0 ||
      camera.name.toLowerCase().includes(normalizedSearch) ||
      camera.vendor.toLowerCase().includes(normalizedSearch) ||
      camera.product.toLowerCase().includes(normalizedSearch)

    const matchesCriticity =
      criticityFilter === 'all' || camera.criticity === criticityFilter

    return matchesSearch && matchesCriticity
  })

  if (isLoading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="text-center text-gray-400">Chargement...</div>
      </div>
    )
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-3xl font-bold text-white">Gestion Caméras</h1>
        <button
          onClick={() => setIsAddingCamera(true)}
          className="cyber-button"
        >
          Ajouter Caméra
        </button>
      </div>

      {/* Add Camera Form */}
      {isAddingCamera && (
        <div className="threat-card mb-6">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Nom</label>
              <input
                type="text"
                value={newCamera.name}
                onChange={(e) => setNewCamera(prev => ({ ...prev, name: e.target.value }))}
                className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
                placeholder="Nom de la caméra"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Marque</label>
              <select
                value={newCamera.vendor}
                onChange={(e) => setNewCamera(prev => ({ ...prev, vendor: e.target.value, product: '' }))}
                className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
              >
                <option value="">Sélectionner une marque</option>
                {Object.keys(CAMERA_MODELS).map(vendor => (
                  <option key={vendor} value={vendor}>{vendor}</option>
                ))}
                <option value="Autre">Autre</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Modèle</label>
              {newCamera.vendor === 'Autre' || !newCamera.vendor ? (
                <input
                  type="text"
                  value={newCamera.product}
                  onChange={(e) => setNewCamera(prev => ({ ...prev, product: e.target.value }))}
                  className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
                  placeholder="Modèle"
                />
              ) : (
                <select
                  value={newCamera.product}
                  onChange={(e) => setNewCamera(prev => ({ ...prev, product: e.target.value }))}
                  className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
                >
                  <option value="">Sélectionner un modèle</option>
                  {CAMERA_MODELS[newCamera.vendor as keyof typeof CAMERA_MODELS]?.map(model => (
                    <option key={model} value={model}>{model}</option>
                  ))}
                </select>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Criticité</label>
              <select
                value={newCamera.criticity}
                onChange={(e) => setNewCamera(prev => ({ ...prev, criticity: e.target.value as any }))}
                className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
              >
                <option value="low">Faible</option>
                <option value="medium">Moyenne</option>
                <option value="high">Élevée</option>
                <option value="critical">Critique</option>
              </select>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleAddCamera}
                className="px-4 py-2 bg-cyber-blue text-dark-bg rounded font-semibold hover:bg-opacity-80"
              >
                ✓
              </button>
              <button
                onClick={() => {
                  setIsAddingCamera(false)
                  setNewCamera({ name: '', vendor: '', product: '', criticity: 'medium' })
                }}
                className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                ✕
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Search and Filter Controls */}
      <div className="threat-card mb-6">
        <div className="flex flex-col sm:flex-row gap-4 items-center">
          <div className="flex-1">
            <label className="block text-sm font-medium text-gray-300 mb-1">Rechercher</label>
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white placeholder-gray-400"
              placeholder="Rechercher par nom, marque ou modèle..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Filtrer par Criticité</label>
            <select
              value={criticityFilter}
              onChange={(e) => setCriticityFilter(e.target.value)}
              className="px-3 py-2 bg-dark-bg border border-gray-600 rounded text-white"
            >
              <option value="all">Toutes les criticités</option>
              <option value="critical">Critique</option>
              <option value="high">Élevée</option>
              <option value="medium">Moyenne</option>
              <option value="low">Faible</option>
            </select>
          </div>
          <div className="text-sm text-gray-400">
            {filteredCameras.length} caméra{filteredCameras.length !== 1 ? 's' : ''} trouvée{filteredCameras.length !== 1 ? 's' : ''}
          </div>
        </div>
      </div>

      {/* Cameras Table */}
      <div className="threat-card">
        {filteredCameras.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            {cameras.length === 0 
              ? 'Aucune caméra trouvée. Cliquez sur "Ajouter Caméra" pour commencer.'
              : 'Aucune caméra ne correspond aux critères de recherche.'
            }
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-gray-600">
                  <th className="py-3 px-4 text-cyber-blue font-semibold">Nom</th>
                  <th className="py-3 px-4 text-cyber-blue font-semibold">Marque</th>
                  <th className="py-3 px-4 text-cyber-blue font-semibold">Modèle</th>
                  <th className="py-3 px-4 text-cyber-blue font-semibold">Criticité</th>
                  <th className="py-3 px-4 text-cyber-blue font-semibold">Statut Sync</th>
                  <th className="py-3 px-4 text-cyber-blue font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredCameras.map((camera) => (
                  <tr key={camera.id} className="border-b border-gray-700">
                    {camera.isEditing ? (
                      <>
                        <td className="py-3 px-4">
                          <input
                            type="text"
                            value={camera.name}
                            onChange={(e) => setCameras(prev => prev.map(c =>
                              c.id === camera.id ? { ...c, name: e.target.value } : c
                            ))}
                            className="w-full px-2 py-1 bg-dark-bg border border-gray-600 rounded text-white text-sm"
                          />
                        </td>
                        <td className="py-3 px-4">
                          <select
                            value={camera.vendor}
                            onChange={(e) => setCameras(prev => prev.map(c =>
                              c.id === camera.id ? { ...c, vendor: e.target.value, product: '' } : c
                            ))}
                            className="w-full px-2 py-1 bg-dark-bg border border-gray-600 rounded text-white text-sm"
                          >
                            <option value="">Sélectionner une marque</option>
                            {Object.keys(CAMERA_MODELS).map(vendor => (
                              <option key={vendor} value={vendor}>{vendor}</option>
                            ))}
                            <option value="Autre">Autre</option>
                          </select>
                        </td>
                        <td className="py-3 px-4">
                          {camera.vendor === 'Autre' || !Object.keys(CAMERA_MODELS).includes(camera.vendor) ? (
                            <input
                              type="text"
                              value={camera.product}
                              onChange={(e) => setCameras(prev => prev.map(c =>
                                c.id === camera.id ? { ...c, product: e.target.value } : c
                              ))}
                              className="w-full px-2 py-1 bg-dark-bg border border-gray-600 rounded text-white text-sm"
                            />
                          ) : (
                            <select
                              value={camera.product}
                              onChange={(e) => setCameras(prev => prev.map(c =>
                                c.id === camera.id ? { ...c, product: e.target.value } : c
                              ))}
                              className="w-full px-2 py-1 bg-dark-bg border border-gray-600 rounded text-white text-sm"
                            >
                              <option value="">Sélectionner un modèle</option>
                              {CAMERA_MODELS[camera.vendor as keyof typeof CAMERA_MODELS]?.map(model => (
                                <option key={model} value={model}>{model}</option>
                              ))}
                            </select>
                          )}
                        </td>
                        <td className="py-3 px-4">
                          <select
                            value={camera.criticity}
                            onChange={(e) => setCameras(prev => prev.map(c =>
                              c.id === camera.id ? { ...c, criticity: e.target.value as any } : c
                            ))}
                            className="w-full px-2 py-1 bg-dark-bg border border-gray-600 rounded text-white text-sm"
                          >
                            <option value="low">Faible</option>
                            <option value="medium">Moyenne</option>
                            <option value="high">Élevée</option>
                            <option value="critical">Critique</option>
                          </select>
                        </td>
                        <td className="py-3 px-4">
                          {getSyncStatusDisplay(camera)}
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex gap-2">
                            <button
                              onClick={() => handleSaveEdit(camera)}
                              className="w-8 h-8 bg-cyber-blue text-dark-bg rounded hover:bg-opacity-80 flex items-center justify-center"
                            >
                              ✓
                            </button>
                            <button
                              onClick={() => handleCancelEdit(camera.id)}
                              className="w-8 h-8 bg-gray-600 text-white rounded hover:bg-gray-700 flex items-center justify-center"
                            >
                              ✕
                            </button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="py-3 px-4 font-medium text-white">{camera.name}</td>
                        <td className="py-3 px-4 text-gray-300">{camera.vendor}</td>
                        <td className="py-3 px-4 text-gray-300">{camera.product}</td>
                        <td className="py-3 px-4">
                          <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold border ${
                            camera.criticity === 'critical'
                              ? 'bg-red-500/20 text-red-400 border-red-500/50'
                              : camera.criticity === 'high'
                                ? 'bg-orange-500/20 text-orange-400 border-orange-500/50'
                                : camera.criticity === 'medium'
                                  ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
                                  : 'bg-green-500/20 text-green-400 border-green-500/50'
                          }`}>
                            {camera.criticity === 'low' ? 'Faible' :
                             camera.criticity === 'medium' ? 'Moyenne' :
                             camera.criticity === 'high' ? 'Élevée' : 'Critique'}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          {getSyncStatusDisplay(camera)}
                        </td>
                        <td className="py-3 px-4">
                          <div className="relative">
                            <details className="relative">
                              <summary className="cursor-pointer text-gray-400 hover:text-white">
                                ⋯
                              </summary>
                              <div className="absolute right-0 mt-2 w-32 bg-dark-card border border-gray-600 rounded shadow-lg z-10">
                                <button
                                  onClick={() => handleEdit(camera.id)}
                                  className="block w-full text-left px-4 py-2 text-gray-300 hover:bg-gray-700"
                                >
                                  Modifier
                                </button>
                                <button
                                  onClick={() => setDeleteModal({ isOpen: true, camera })}
                                  className="block w-full text-left px-4 py-2 text-red-400 hover:bg-gray-700"
                                >
                                  Supprimer
                                </button>
                              </div>
                            </details>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Delete Modal */}
      {deleteModal.isOpen && deleteModal.camera && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-dark-card border border-gray-600 rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-white mb-4">
              Confirmer la suppression
            </h3>
            <p className="text-gray-300 mb-6">
              Êtes-vous sûr de vouloir supprimer la caméra "{deleteModal.camera.name}" ?
              Cette action est irréversible.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteModal({ isOpen: false })}
                className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                Annuler
              </button>
              <button
                onClick={() => deleteModal.camera && handleDelete(deleteModal.camera)}
                className="px-4 py-2 bg-cyber-red text-white rounded hover:bg-red-700"
              >
                Supprimer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
