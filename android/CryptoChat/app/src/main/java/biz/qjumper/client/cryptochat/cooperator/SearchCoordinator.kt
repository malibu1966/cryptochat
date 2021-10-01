package biz.qjumper.client.cryptochat.cooperator

object SearchCoordinator {

    lateinit var searchFinishedCallback: (loggedIn: Boolean) -> NavigationDestination

    fun start(
        bookSearchRepository: BookSearchRepository,
        callback: (loggedIn: Boolean) -> NavigationDestination
    ): NavigationDeepLinkDestination {
        searchFinishedCallback = callback
        return startSearchOnScreen(
            bookSearchRepository
        ).asDeepLink()
    }

    internal fun navigateFromLandingPage(): NavigationDestination {
        return SearchPage2Destination().asDeepLink()
    }

    internal fun navigateFromSearchResults(title: String): NavigationDestination {
        return SearchDetailDestination(SearchDetailData(title))
    }

    internal fun navigateFromSearchDetail(): NavigationDestination {
        return SearchExtrasDestination()
    }

    internal fun finish(loggedIn: Boolean): NavigationDestination {
        return searchFinishedCallback(loggedIn)
    }

    internal fun error(): NavigationDestination {
        Timber.e("TODO: Implement Error State")
        return SearchDetailDestination(SearchDetailData("Error"))
    }

    internal fun navigateBackFromSearchResults(): NavigationDestination {
        return SearchPage2Destination()
    }

    private fun startSearchOnScreen(bookSearchRepository: BookSearchRepository): NavigationDestination {
        if (skipSearchLandingScreen(bookSearchRepository) &&
            skipPage2(bookSearchRepository)
        ) {
            return SearchResultsDestination()
        } else if (skipPage1(bookSearchRepository)) {
            return SearchPage2Destination()
        }
        return SearchLandingDestination()
    }
}