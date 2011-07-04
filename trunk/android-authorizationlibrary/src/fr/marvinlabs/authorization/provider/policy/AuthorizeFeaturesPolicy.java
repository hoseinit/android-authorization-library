package fr.marvinlabs.authorization.provider.policy;

import java.util.Arrays;

import android.net.Uri;
import android.net.Uri.Builder;

/**
 * Authorize only a given set of features
 * 
 * @author Vincent Prat @ MarvinLabs
 */
public class AuthorizeFeaturesPolicy extends AuthorizePackagePolicy {

	private String queriedFeature;
	private String[] authorizedFeatures;

	/**
	 * Create a new instance of this class to be used to authorize a query
	 * 
	 * @param authorizedFeatures
	 *            The set of features that are authorized
	 * @return The policy
	 */
	public static AuthorizeFeaturesPolicy newInstanceForAuthorization(String packageName, String[] authorizedFeatures) {
		AuthorizeFeaturesPolicy policy = new AuthorizeFeaturesPolicy(packageName);

		// The array must be sorted so that we can use the {@link java.util.Arrays#binarySearch(Object[], Object)}
		// function later on.
		policy.authorizedFeatures = authorizedFeatures;
		Arrays.sort(policy.authorizedFeatures);

		return policy;
	}

	/**
	 * Create a new instance of this class to be used to build a query
	 * 
	 * @param queriedFeature
	 *            The feature we want to authorize
	 * @return The policy
	 */
	public static AuthorizeFeaturesPolicy newInstanceForQuery(String packageName, String queriedFeature) {
		AuthorizeFeaturesPolicy policy = new AuthorizeFeaturesPolicy(packageName);
		policy.queriedFeature = queriedFeature;
		return policy;
	}

	@Override
	public String getUriMatcherPath() {
		return super.getUriMatcherPath() + "/features/*";
	}

	@Override
	public Uri getQueryUri() {
		if (queriedFeature == null) return null;
		return getBaseUriBuilder().appendPath(queriedFeature).build();
	}

	@Override
	public String[] getQuerySelectionArgs() {
		return null;
	}

	@Override
	public boolean isAuthorized(Uri uri, String[] selectionArgs) {
		// The package name must be coherent
		if (!super.isAuthorized(uri, selectionArgs)) return false;

		// Feature name is supplied as the last segment of the path of the URI. Check to see if we find it.
		final String feature = uri.getLastPathSegment();
		if (Arrays.binarySearch(authorizedFeatures, feature) >= 0) return true;

		return false;
	}

	@Override
	protected Builder getBaseUriBuilder() {
		return super.getBaseUriBuilder().appendPath("features");
	}

	/**
	 * We don't want anybody to instanciate directly the class
	 */
	protected AuthorizeFeaturesPolicy(String packageName) {
		super(packageName);
	}
}
