package biz.qjumper.client.cryptochat.ui.contacts

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import biz.qjumper.client.cryptochat.R
import biz.qjumper.client.cryptochat.coordinators.MainCoodinator

class ContactsFragment : Fragment() {

    private lateinit var dashboardViewModel: ContactsViewModel

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        MainCoodinator.registerFragment(this)
        dashboardViewModel =
                ViewModelProvider(this).get(ContactsViewModel::class.java)
        val root = inflater.inflate(R.layout.fragment_contacts, container, false)
        //val textView: TextView = root.findViewById(R.id.text_dashboard)
//        dashboardViewModel.text.observe(viewLifecycleOwner, Observer {
//            textView.text = it
//        })
        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        MainCoodinator.setupView()
    }

    override fun onResume() {
        super.onResume()

    }
}