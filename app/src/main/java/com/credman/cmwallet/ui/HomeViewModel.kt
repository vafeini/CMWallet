package com.credman.cmwallet.ui

import android.util.Log
import androidx.credentials.CreateDigitalCredentialRequest
import androidx.credentials.CreateDigitalCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.credman.cmwallet.CmWalletApplication
import com.credman.cmwallet.CmWalletApplication.Companion.TAG
import com.credman.cmwallet.MainActivity
import com.credman.cmwallet.data.model.CredentialItem
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import org.json.JSONObject

data class HomeScreenUiState(
    val credentials: List<CredentialItem>
)

class HomeViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(HomeScreenUiState(emptyList()))
    val uiState: StateFlow<HomeScreenUiState> = _uiState.asStateFlow()

    init {
        viewModelScope.launch {
            CmWalletApplication.credentialRepo.credentials.collect { credentials ->
                _uiState.update { currentState ->
                    currentState.copy(
                        credentials = credentials
                    )
                }
            }
        }
    }

    fun deleteCredential(id: String) {
        CmWalletApplication.credentialRepo.deleteCredential(id)
    }
}