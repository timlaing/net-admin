"""CSRF-protected web forms."""

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, EqualTo, Length, Regexp


class LoginForm(FlaskForm):
    """Login form."""

    username = StringField("Username", validators=[DataRequired(), Length(max=253)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=1024)])
    submit = SubmitField("Sign in")


class PasswordForm(FlaskForm):
    """Self-service password change form."""

    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField(
        "New password", validators=[DataRequired(), Length(min=12, max=1024)]
    )
    confirm_password = PasswordField(
        "Confirm new password", validators=[DataRequired(), EqualTo("new_password")]
    )
    submit = SubmitField("Change password")


class DnsRecordForm(FlaskForm):
    """DNS record mutation form."""

    zone = StringField("Zone", validators=[DataRequired(), Length(max=253)])
    name = StringField("Name", validators=[DataRequired(), Length(max=253)])
    record_type = SelectField(
        "Type",
        choices=[("A", "A"), ("AAAA", "AAAA"), ("PTR", "PTR"), ("CNAME", "CNAME"), ("TXT", "TXT")],
    )
    value = StringField("Value", validators=[DataRequired(), Length(max=1024)])
    ttl = StringField("TTL", default="300", validators=[Regexp(r"^[1-9][0-9]{0,8}$")])
    submit = SubmitField("Save record")


class DeleteDnsForm(FlaskForm):
    """DNS record deletion form."""

    zone = StringField(validators=[DataRequired()])
    name = StringField(validators=[DataRequired()])
    record_type = StringField(validators=[DataRequired()])
    value = StringField()
    submit = SubmitField("Delete")


class RpiRecordForm(FlaskForm):
    """Paired Raspberry Pi forward/reverse DNS form."""

    hostname = StringField("Hostname", validators=[DataRequired(), Regexp(r"^[A-Za-z0-9-]+$")])
    address = StringField("IPv4 address", validators=[DataRequired(), Length(max=45)])
    forward_zone = StringField("Forward zone", validators=[DataRequired(), Length(max=253)])
    reverse_zone = StringField("Reverse zone", validators=[DataRequired(), Length(max=253)])
    ttl = StringField("TTL", default="300", validators=[Regexp(r"^[1-9][0-9]{0,8}$")])
    submit = SubmitField("Create forward and reverse records")


class ReservationForm(FlaskForm):
    """DHCP reservation mutation form."""

    name = StringField("Host name", validators=[DataRequired(), Regexp(r"^[A-Za-z0-9_-]+$")])
    mac = StringField(
        "MAC address",
        validators=[DataRequired(), Regexp(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")],
    )
    address = StringField("IPv4 address", validators=[DataRequired()])
    submit = SubmitField("Save reservation")


class DhcpSubnetForm(FlaskForm):
    """DHCP subnet pool and option editing form."""

    network = StringField("Subnet network", validators=[DataRequired(), Length(max=45)])
    ranges = TextAreaField("Pools (start-end, one per line; blank removes all pools)")
    options = TextAreaField("Options (name=value, one per line)")
    submit = SubmitField("Update subnet")


class RadiusUserForm(FlaskForm):
    """RADIUS user mutation form."""

    username = StringField("Username", validators=[DataRequired(), Regexp(r"^[A-Za-z0-9_.@-]+$")])
    password = PasswordField("Password", validators=[Length(min=12, max=1024)])
    role = SelectField("Role", choices=[("standard", "Standard"), ("admin", "Administrator")])
    disabled = BooleanField("Disabled")
    submit = SubmitField("Save user")


class RadiusClientForm(FlaskForm):
    """RADIUS client mutation form."""

    name = StringField("Name", validators=[DataRequired(), Regexp(r"^[A-Za-z0-9_.-]+$")])
    address = StringField("IP address or CIDR", validators=[DataRequired(), Length(max=128)])
    shortname = StringField("Short name", validators=[DataRequired(), Length(max=128)])
    secret = PasswordField("Shared secret", validators=[DataRequired(), Length(min=16, max=1024)])
    submit = SubmitField("Save client")


class DnsZoneForm(FlaskForm):
    """Create a complete authoritative zone through the restricted agent."""

    name = StringField("Zone name", validators=[DataRequired(), Length(max=253)])
    content = TextAreaField(
        "Zone file contents (including SOA and NS)",
        validators=[DataRequired(), Length(max=1_000_000)],
    )
