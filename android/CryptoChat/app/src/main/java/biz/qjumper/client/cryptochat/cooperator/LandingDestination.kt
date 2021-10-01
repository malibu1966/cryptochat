package biz.qjumper.client.cryptochat.cooperator

import android.os.Bundle
import androidx.core.os.bundleOf
import biz.qjumper.client.cryptochat.R

class LandingDestination : NavigationDestination(R.id.numb  erflow_navigation)

class LandingDestinationData(private val data: Boolean) : NavigationArguments {
    override fun getBundle(): Bundle {
        return bundleOf(
            BUNDLE_KEY to data
        )
    }
}