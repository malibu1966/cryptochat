package biz.qjumper.client.cryptochat.ui.settings

import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.fragment.findNavController
import biz.qjumper.client.cryptochat.R
import biz.qjumper.client.cryptochat.coordinators.MainCoodinator
import biz.qjumper.client.cryptochat.coordinators.RootCoordinator
import biz.qjumper.client.cryptochat.databinding.FragmentSettingsBinding

class SettingsFragment : Fragment() {

    private lateinit var notificationsViewModel: SettingsViewModel
    private var _binding : FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        notificationsViewModel =
                ViewModelProvider(this).get(SettingsViewModel::class.java)
        val root = inflater.inflate(R.layout.fragment_settings, container, false)
//        val textView: TextView = root.findViewById(R.id.text_notifications)
//        notificationsViewModel.text.observe(viewLifecycleOwner, Observer {
//            textView.text = it
//        })
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)

        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        MainCoodinator.registerFragment(this)
        binding.settingsLogoutBtn.setOnClickListener {
            MainCoodinator.logout()
            findNavController().navigate(R.id.action_navigation_settings_to_fragment_login)
        }
    }
}