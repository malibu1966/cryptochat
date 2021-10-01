package biz.qjumper.client.cryptochat.cooperator

import android.os.Bundle
import androidx.annotation.IdRes

open class NavigationDestination(
    private val id: Int,
    private val navigationArguments: Bundle? = null
) {
    /**
     * Generates a navigation event from the [id] and [navigationArguments] of the
     * [NavigationDestination] class.
     */
    fun buildEvent(): NavigationEvent = NavigationEvent(id, navigationArguments)
}

/**
 * Class to wrap the navigation ID and appropriate arguments that need to be in the bundle while switching between fragments.
 *
 * @param navId = the ID to navigate too
 * @param navigationArguments: The Map of keys to values of various parameters that need to be passed into the next screen.
 */
data class NavigationEvent(@IdRes val navId: Int, val navigationArguments: Bundle? = null) {
}

interface NavigationArguments {
    fun getBundle(): Bundle
}