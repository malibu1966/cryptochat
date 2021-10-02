package biz.qjumper.client.cryptochat.ui.user.login

import androidx.lifecycle.ViewModelProvider
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import biz.qjumper.client.cryptochat.coordinators.LoginCoordinator
import biz.qjumper.client.cryptochat.databinding.FragmentLoginBinding
import biz.qjumper.client.cryptochat.managers.PersistenceManager

class LoginFragment : Fragment() {
    companion object {
        fun newInstance() = LoginFragment()
    }

    private lateinit var viewModel: LoginViewModel
    private var _binding : FragmentLoginBinding? = null
    private val binding get() = _binding!!

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProvider(this).get(LoginViewModel::class.java)
//        val loginObserver = Observer<Constants.LoginStatus> { loggedIn ->
//            // Update the UI, in this case, a TextView.
//            //nameTextView.text = newName
//            if (loggedIn==Constants.LoginStatus.RESET) {
//                binding.loginErrorTv.visibility = View.INVISIBLE
//                findNavController().popBackStack(R.id.navigation_settings, true)
//            }
//            else if (loggedIn==Constants.LoginStatus.LOGGED_IN) {
//                binding.loginErrorTv.visibility = View.INVISIBLE
//                RootCoordinator.startMain()
//            }
//            else {
//                binding.loginErrorTv.visibility = View.VISIBLE
//            }
//        }
//        viewModel.loggedIn.observe(this, loginObserver)
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        viewModel = ViewModelProvider(this).get(LoginViewModel::class.java)
        LoginCoordinator.registerFragment(this)
        _binding = FragmentLoginBinding.inflate(inflater, container, false)
        binding.loginUsernameEt.setText(PersistenceManager.getUsername())
        val view = binding.root
        LoginCoordinator.setupCallbacks(viewModel, _binding!!)
        return view
    }


    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        viewModel = ViewModelProvider(this).get(LoginViewModel::class.java)
        LoginCoordinator.setupView()

        // TODO: Use the ViewModel
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }



}