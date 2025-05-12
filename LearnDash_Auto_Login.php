<?php
/**
 * Plugin Name: LearnDash Auto Login Links
 * Description: Creates unique auto-login links for LearnDash members using WP Fusion
 * Version: 1.0
 */

if (!defined('ABSPATH')) {
    exit;
}

class LearnDash_Auto_Login {

    private $batch_size = 100;

//    public function __construct() {
//        add_action('init', array($this, 'handle_auto_login'));
//        add_filter('wp_fusion_user_meta', array($this, 'add_auto_login_token'), 10, 2);
//        add_action('user_register', array($this, 'generate_user_token'), 20);
//        add_action('show_user_profile', array($this, 'show_auto_login_field'));
//        add_action('edit_user_profile', array($this, 'show_auto_login_field'));
//        add_action('process_token_generation_batch', array($this, 'generate_missing_tokens'));
//        //add_action('admin_init', array($this, 'generate_missing_tokens'));
//    }
    public function __construct() {
        add_action('init', array($this, 'handle_auto_login'));
        add_filter('wp_fusion_user_meta', array($this, 'add_auto_login_token'), 10, 2);
        add_action('bp_complete_signup', array($this, 'generate_user_token'), 99);
        add_action('show_user_profile', array($this, 'show_auto_login_field'));
        add_action('edit_user_profile', array($this, 'show_auto_login_field'));
        add_action('process_token_generation_batch', array($this, 'generate_missing_tokens'));

        // Add debug logging
        add_action('wp_footer', array($this, 'debug_registration'));
    }

    public function debug_registration() {
        error_log('Registration Debug - User ID: ' . get_current_user_id());
        error_log('BP Profile Groups: ' . print_r(BP_XProfile_Group::get(), true));
    }

//    public function generate_user_token($user_id) {
//        $token = $this->generate_token();
//        update_user_meta($user_id, 'auto_login_token', $token);
//
//        if (function_exists('wp_fusion')) {
//            wp_fusion()->user->push_user_meta(array(
//                'auto_login_token' => $token
//            ), $user_id);
//        }
//    }
    public function generate_user_token($user_id) {
        if (!$user_id || !is_numeric($user_id)) {
            return;
        }

        $token = $this->generate_token();
        update_user_meta($user_id, 'auto_login_token', $token);

        if (function_exists('wp_fusion')) {
            wp_fusion()->user->push_user_meta(array(
                'auto_login_token' => $token
            ), $user_id);
        }
    }

    public function add_auto_login_token($meta, $user_id) {
        $token = get_user_meta($user_id, 'auto_login_token', true);
        if (!empty($token)) {
            $meta['auto_login_token'] = $token;
        }
        return $meta;
    }

    public function handle_auto_login() {
        if (!isset($_GET['autologin']) || empty($_GET['token'])) {
            return;
        }

        $token = sanitize_text_field($_GET['token']);

        // Debug log
        error_log('Auto Login Attempt - Token: ' . $token);

        $users = get_users(array(
            'meta_key' => 'auto_login_token',
            'meta_value' => $token,
            'number' => 1
        ));

        // Debug log
        error_log('Users found: ' . print_r($users, true));

        if (empty($users)) {
            wp_die('Invalid login token');
        }

        $user = $users[0];

        if (!is_user_logged_in()) {
            wp_clear_auth_cookie();
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID, true);
        }

        // Debug log
        error_log('User logged in: ' . $user->ID);

        $redirect = isset($_GET['redirect_to'])
            ? esc_url_raw($_GET['redirect_to'])
            : home_url('/courses/');

        wp_redirect($redirect);
        exit;
    }

    public function generate_token() {
        return hash('sha256', uniqid() . time());
    }

    public static function get_login_url($user_id, $redirect_to = '') {
        $token = get_user_meta($user_id, 'auto_login_token', true);

        if (empty($token)) {
            $instance = new self();
            $token = $instance->generate_token();
            update_user_meta($user_id, 'auto_login_token', $token);
        }

        $args = array(
            'autologin' => 1,
            'token' => $token
        );

        if (!empty($redirect_to)) {
            $args['redirect_to'] = urlencode($redirect_to);
        }

        return add_query_arg($args, home_url());
    }

    public function show_auto_login_field($user) {
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }

        // Generate token if it doesn't exist when viewing profile
        $token = get_user_meta($user->ID, 'auto_login_token', true);
        if (empty($token)) {
            $token = $this->generate_token();
            update_user_meta($user->ID, 'auto_login_token', $token);

            if (function_exists('wp_fusion')) {
                wp_fusion()->user->push_user_meta(array(
                    'auto_login_token' => $token
                ), $user->ID);
            }
        }

        $login_url = self::get_login_url($user->ID);
        ?>
        <h3>Auto Login URL</h3>
        <table class="form-table">
            <tr>
                <th><label for="auto-login-url">Login URL</label></th>
                <td>
                    <input type="text" class="regular-text" id="auto-login-url" value="<?php echo esc_url($login_url); ?>" readonly />
                    <button type="button" class="button" onclick="copyLoginUrl()">Copy URL</button>
                    <button type="button" class="button" onclick="regenerateToken(<?php echo $user->ID; ?>)">Generate New URL</button>
                    <script>
                        function copyLoginUrl() {
                            var urlField = document.getElementById('auto-login-url');
                            urlField.select();
                            document.execCommand('copy');
                            alert('URL copied to clipboard!');
                        }

                        function regenerateToken(userId) {
                            if (confirm('Are you sure you want to generate a new login URL? The old URL will stop working.')) {
                                var data = {
                                    'action': 'regenerate_login_token',
                                    'user_id': userId,
                                    'nonce': '<?php echo wp_create_nonce('regenerate_login_token'); ?>'
                                };

                                jQuery.post(ajaxurl, data, function(response) {
                                    if (response.success) {
                                        document.getElementById('auto-login-url').value = response.data.new_url;
                                        alert('New URL generated successfully!');
                                    } else {
                                        alert('Error generating new URL');
                                    }
                                });
                            }
                        }
                    </script>
                </td>
            </tr>
        </table>
        <?php
    }

    // Add this new method
    public function generate_missing_tokens() {
        global $pagenow;
        if ($pagenow != 'users.php') {
            return;
        }

        $offset = get_option('auto_login_token_offset', 0);

        $users = get_users(array(
            'meta_query' => array(
                array(
                    'key' => 'auto_login_token',
                    'compare' => 'NOT EXISTS'
                )
            ),
            'number' => $this->batch_size,
            'offset' => $offset
        ));

        if (empty($users)) {
            delete_option('auto_login_token_offset');
            return;
        }

        foreach ($users as $user) {
            $this->generate_user_token($user->ID);
        }

        update_option('auto_login_token_offset', $offset + $this->batch_size);

        // Schedule next batch
        wp_schedule_single_event(time() + 30, 'process_token_generation_batch');
    }

    public function regenerate_login_token() {
        check_ajax_referer('regenerate_login_token', 'nonce');

        if (!current_user_can('edit_users')) {
            wp_send_json_error('Permission denied');
        }

        $user_id = intval($_POST['user_id']);
        $token = $this->generate_token();
        update_user_meta($user_id, 'auto_login_token', $token);

        if (function_exists('wp_fusion')) {
            wp_fusion()->user->push_user_meta(array(
                'auto_login_token' => $token
            ), $user_id);
        }

        wp_send_json_success(array(
            'new_url' => self::get_login_url($user_id)
        ));
    }
}

$learndash_auto_login = new LearnDash_Auto_Login();
add_action('wp_ajax_regenerate_login_token', array($learndash_auto_login, 'regenerate_login_token'));

function learndash_get_auto_login_url($user_id, $redirect_to = '') {
    return LearnDash_Auto_Login::get_login_url($user_id, $redirect_to);
}
