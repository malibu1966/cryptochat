package biz.qjumper.client.cryptochat.ui.security

import androidx.lifecycle.ViewModelProvider
import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import biz.qjumper.client.cryptochat.R
import biz.qjumper.client.cryptochat.coordinators.MainCoodinator

class SecurityFragment : Fragment() {

    companion object {
        fun newInstance() = SecurityFragment()
    }

    private lateinit var viewModel: SecurityViewModel

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_security, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        MainCoodinator.registerFragment(this)
        MainCoodinator.setupView()
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        viewModel = ViewModelProvider(this).get(SecurityViewModel::class.java)
        // TODO: Use the ViewModel
    }

}