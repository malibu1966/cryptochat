package biz.qjumper.client.cryptochat.ui.chat

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.Observer
import androidx.lifecycle.ViewModelProvider
import biz.qjumper.client.cryptochat.R
import biz.qjumper.client.cryptochat.coordinators.MainCoodinator
import biz.qjumper.client.cryptochat.databinding.FragmentChatBinding

class ChatFragment : Fragment() {

    private lateinit var homeViewModel: ChatViewModel
    private var _binding : FragmentChatBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
            inflater: LayoutInflater,
            container: ViewGroup?,
            savedInstanceState: Bundle?
    ): View? {
        homeViewModel =
                ViewModelProvider(this).get(ChatViewModel::class.java)
        val root = inflater.inflate(R.layout.fragment_chat, container, false)
        homeViewModel.text.observe(viewLifecycleOwner, Observer {
            //textView.text = it
        })
        _binding
        return root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        MainCoodinator.registerFragment(this)
        MainCoodinator.setupView()
    }
}