package biz.qjumper.client.cryptochat.cooperator

object RootCoordinator {

    fun start(): NavigationDestination {
        return MainDestination()
    }

    internal fun navigateFromMainFragment(): NavigationDestination {
        return LandingDestination()
    }

//    internal fun displayLoginModule(func: () -> NavigationDestination): NavigationDestination {
//        return LoginCoordinator.getInstance(func).start()
//    }
//
//    internal fun displaySearchModule(hotelSearchRepository: HotelSearchRepository): NavigationDestination {
//        return SearchCoordinator.start(hotelSearchRepository, ::searchCoordinatorFinished)
//    }
//
//    private fun displayPurchaseModule(): NavigationDestination {
//        return PurchaseCoordinator.getInstance(::purchaseCoordinatorFinished).start()
//    }
//
//    private fun searchCoordinatorFinished(loggedIn: Boolean): NavigationDestination {
//        val func: () -> NavigationDestination = ::displayPurchaseModule
//        return ensureAuthenticatedAndThen(loggedIn, func)
//    }

    private fun ensureAuthenticatedAndThen(
        loggedIn: Boolean,
        func: () -> NavigationDestination
    ): NavigationDestination {
        return if (loggedIn) {
            func()
        } else {
            displayLoginModule(func)
        }
    }

    private fun purchaseCoordinatorFinished() {
        Timber.d("Not yet Implemented")
    }
}