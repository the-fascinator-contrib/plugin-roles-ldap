/*
 * The Fascinator - LDAP Roles plugin
 * Copyright (C) 2010-2011 University of Southern Queensland
 * Copyright (C) 2012 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package com.googlecode.fascinator.roles.ldap;

import com.googlecode.fascinator.api.PluginDescription;
import com.googlecode.fascinator.api.roles.Roles;
import com.googlecode.fascinator.api.roles.RolesException;
import com.googlecode.fascinator.authentication.ldap.LdapAuthenticationHandler;
import com.googlecode.fascinator.common.JsonSimple;
import com.googlecode.fascinator.common.JsonSimpleConfig;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * This plugin implements ldap roles.
 * </p>
 * 
 * <h3>Configuration</h3>
 * <p>
 * Standard configuration table:
 * </p>
 * <table border="1">
 * <tr>
 * <th>Option</th>
 * <th>Description</th>
 * <th>Required</th>
 * <th>Default</th>
 * </tr>
 * 
 * <tr>
 * <td>ldap/baseURL</td>
 * <td>URL of the LDAP server</td>
 * <td><b>Yes</b></td>
 * <td>ldap://ldap.uq.edu.au:389</td>
 * </tr>
 * <tr>
 * <td>ldap/baseDN</td>
 * <td>The base Distinguished Name to search under</td>
 * <td><b>Yes</b></td>
 * <td>ou=people,o=The University of Queensland,c=AU</td>
 * </tr>
 * <tr>
 * <td>ldap/idAttribute</td>
 * <td>The name of the attribute for which the username will be searched under</td>
 * <td><b>Yes</b></td>
 * <td>uid</td>
 * </tr>
 * <tr>
 * <td>ldap/objectClassRoleMap</td>
 * <td>This value maps objectClass values from LDAP to the fascinator roles. If
 * the objectClass does not exist in the mapping, the user will not have any
 * roles.</td>
 * <td><b>Yes</b></td>
 * <td> [{
                    "objectClass": "person"
                    "roles": ["registered"]
                    
                }]</td>
 * </tr>
 * 
 * </table>
 * 
 * <h3>Examples</h3>
 * <ol>
 * <li>
 * Using ldap role plugin in The Fascinator
 * 
 * <pre>
 *      "roles": {
 *          "type": "ldap",
 *          "ldap": {
 *                "baseURL": "ldap://ldap.uq.edu.au:389",
 *                "baseDN": "ou=people,o=The University of Queensland,c=AU",
 *                "idAttribute": "uid",
 *                "objectClassRoleMap": [{
 *                  "objectClass": "person"
 *                  "roles": ["registered"]     
 *              }]
 *            }
 *      }
 * </pre>
 * 
 * </li>
 * </ol>
 * 
 * <h3>Wiki Link</h3>
 * <p>
 * None
 * </p>
 * 
 * @author Greg Pendlebury and
 * @author Richard Hammond and
 * @author Andrew Brazzatti
 */

public class LDAPRoles implements Roles {
	@SuppressWarnings("unused")
	private final Logger log = LoggerFactory.getLogger(LDAPRoles.class);

	// Ldap authentication class
	private LdapAuthenticationHandler ldapAuthHandler;

	private String objectClassValue;

	@Override
	public String getId() {
		return "ldap";
	}

	@Override
	public String getName() {
		return "LDAP Roles";
	}

	/**
	 * Gets a PluginDescription object relating to this plugin.
	 * 
	 * @return a PluginDescription
	 */
	@Override
	public PluginDescription getPluginDetails() {
		return new PluginDescription(this);
	}

	@Override
	public void init(String jsonString) throws RolesException {
		try {
			setConfig(new JsonSimpleConfig(jsonString));
		} catch (IOException e) {
			throw new RolesException(e);
		}
	}

	@Override
	public void init(File jsonFile) throws RolesException {
		try {
			setConfig(new JsonSimpleConfig(jsonFile));
		} catch (IOException ioe) {
			throw new RolesException(ioe);
		}
	}

	public void setConfig(JsonSimpleConfig config) throws IOException {
		// Get the basics
		String url = config.getString(null, "roles", "ldap", "baseURL");
		String baseDN = config.getString(null, "roles", "ldap", "baseDN");
		String idAttribute = config.getString(null, "roles", "ldap",
				"idAttribute");
		// objectClassValue = config.getString(null, "roles", "ldap",
		// "objectClassValue");

		Map<String, List<String>> objectClassRolesMap = new HashMap<String, List<String>>();
		List<JsonSimple> objectClassRolesList = config.getJsonSimpleList(
				"roles", "ldap", "objectClassRoleMap");
		if (objectClassRolesList != null) {
			for (JsonSimple q : objectClassRolesList) {
				String objectClass = q.getString(null, "objectClass");
				List<String> rolesList = q.getStringList("roles");
				objectClassRolesMap.put(objectClass, rolesList);

			}
		}

		ldapAuthHandler = new LdapAuthenticationHandler(url, baseDN,
				idAttribute, objectClassRolesMap);
	}

	@Override
	public void shutdown() throws RolesException {
		// No action required
	}

	/**
	 * Find and return all roles this user has.
	 * 
	 * @param username
	 *            The username of the user.
	 * @return An array of role names (String).
	 */
	@Override
	public String[] getRoles(String username) {
		return ldapAuthHandler.getRoles(username).toArray(new String[] {});
	}

	/**
	 * Returns a list of users who have a particular role.
	 * 
	 * @param role
	 *            The role to search for.
	 * @return An array of usernames (String) that have that role.
	 */
	@Override
	public String[] getUsersInRole(String role) {
		return new String[0];
	}

	/**
	 * Method for testing if the implementing plugin allows the creation,
	 * deletion and modification of roles.
	 * 
	 * @return true/false reponse.
	 */
	@Override
	public boolean supportsRoleManagement() {
		return false;
	}

	/**
	 * Assign a role to a user.
	 * 
	 * @param username
	 *            The username of the user.
	 * @param newrole
	 *            The new role to assign the user.
	 * @throws RolesException
	 *             if there was an error during assignment.
	 */
	@Override
	public void setRole(String username, String newrole) throws RolesException {
		throw new RolesException("Cannot set role with LDAP plugin!");
	}

	/**
	 * Remove a role from a user.
	 * 
	 * @param username
	 *            The username of the user.
	 * @param oldrole
	 *            The role to remove from the user.
	 * @throws RolesException
	 *             if there was an error during removal.
	 */
	@Override
	public void removeRole(String username, String oldrole)
			throws RolesException {
		throw new RolesException("Cannot remove role with LDAP plugin!");
	}

	/**
	 * Create a role.
	 * 
	 * @param rolename
	 *            The name of the new role.
	 * @throws RolesException
	 *             if there was an error creating the role.
	 */
	@Override
	public void createRole(String rolename) throws RolesException {
		throw new RolesException(
				"Role creation is not support by this plugin as a "
						+ "stand-alone function. Call setRole() with a new "
						+ "role and it will be created automatically.");
	}

	/**
	 * Delete a role.
	 * 
	 * @param rolename
	 *            The name of the role to delete.
	 * @throws RolesException
	 *             if there was an error during deletion.
	 */
	@Override
	public void deleteRole(String rolename) throws RolesException {
		throw new RolesException("Cannot delete role with LDAP plugin!");
	}

	/**
	 * Rename a role.
	 * 
	 * @param oldrole
	 *            The name role currently has.
	 * @param newrole
	 *            The name role is changing to.
	 * @throws RolesException
	 *             if there was an error during rename.
	 */
	@Override
	public void renameRole(String oldrole, String newrole)
			throws RolesException {
		throw new RolesException("Cannot rename role with LDAP plugin!");
	}

	/**
	 * Returns a list of roles matching the search.
	 * 
	 * @param search
	 *            The search string to execute.
	 * @return An array of role names that match the search.
	 * @throws RolesException
	 *             if there was an error searching.
	 */
	@Override
	public String[] searchRoles(String search) throws RolesException {
		throw new RolesException("Cannot search roles with LDAP plugin!");
	}
}
