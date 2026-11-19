import os
import csv
import io
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from config import Config
from database.models import DatabaseManager
from backend.analysis.statistics import StatisticsAnalyzer

class ExportService:
    """Handles professional CSV, PDF, and PCAP export generation."""

    @staticmethod
    def export_csv(session_id: int) -> tuple[str, str]:
        """
        Export session packets to CSV string.
        Returns (csv_content, filename).
        """
        session = DatabaseManager.get_session(session_id)
        if not session:
            raise ValueError(f"Session #{session_id} not found")

        packets, _ = DatabaseManager.get_packets(session_id, limit=10000)

        output = io.StringIO()
        writer = csv.writer(output)

        # Header row
        writer.writerow([
            "No.", "Timestamp", "Formatted Time",
            "Ethernet Source", "Ethernet Dest", "EtherType",
            "Source IP", "Destination IP", "IP Version", "TTL",
            "Protocol", "Source Port", "Destination Port",
            "Length (Bytes)", "TCP Flags", "Packet Info"
        ])

        for p in packets:
            writer.writerow([
                p.get("packet_number"),
                p.get("timestamp"),
                p.get("formatted_time"),
                p.get("eth_src"),
                p.get("eth_dst"),
                p.get("eth_type"),
                p.get("ip_src"),
                p.get("ip_dst"),
                p.get("ip_version"),
                p.get("ip_ttl"),
                p.get("protocol"),
                p.get("src_port") or "",
                p.get("dst_port") or "",
                p.get("packet_len"),
                p.get("tcp_flags") or "",
                p.get("info") or ""
            ])

        csv_data = output.getvalue()
        filename = f"packetscope_session_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        # Log to export history
        DatabaseManager.log_export(session_id, "csv", filename, len(csv_data))

        return csv_data, filename

    @staticmethod
    def generate_pdf_report(session_id: int) -> str:
        """
        Generate an elegant, professional PDF cybersecurity report with ReportLab.
        Returns the absolute filepath of the generated PDF.
        """
        session = DatabaseManager.get_session(session_id)
        if not session:
            raise ValueError(f"Session #{session_id} not found")

        packets, total_count = DatabaseManager.get_packets(session_id, limit=5000)
        stats = StatisticsAnalyzer.calculate_traffic_stats(packets)

        os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)
        pdf_filename = f"packetscope_report_session_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        pdf_path = os.path.join(Config.REPORTS_FOLDER, pdf_filename)

        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()

        # Custom cybersecurity styles
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0052cc'),
            fontName='Helvetica-Bold',
            spaceAfter=4
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=12
        )
        section_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold',
            spaceBefore=10,
            spaceAfter=6
        )
        cell_style = ParagraphStyle(
            'CellText',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor('#1e293b')
        )
        cell_bold = ParagraphStyle(
            'CellBold',
            parent=styles['Normal'],
            fontSize=8,
            leading=11,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor('#0f172a')
        )

        elements = []

        # Header Banner
        elements.append(Paragraph("PACKETSCOPE", title_style))
        elements.append(Paragraph("Network Traffic Analysis & Protocol Inspection Report", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=14))

        # Metadata Table
        meta_data = [
            [
                Paragraph("<b>Session ID:</b>", cell_bold), Paragraph(str(session['id']), cell_style),
                Paragraph("<b>Interface:</b>", cell_bold), Paragraph(str(session['interface']), cell_style)
            ],
            [
                Paragraph("<b>Session Name:</b>", cell_bold), Paragraph(str(session['name']), cell_style),
                Paragraph("<b>Status:</b>", cell_bold), Paragraph(str(session['status']).upper(), cell_style)
            ],
            [
                Paragraph("<b>Start Time:</b>", cell_bold), Paragraph(str(session['start_time']), cell_style),
                Paragraph("<b>End Time:</b>", cell_bold), Paragraph(str(session['end_time'] or "In progress"), cell_style)
            ],
            [
                Paragraph("<b>Filter Applied:</b>", cell_bold), Paragraph(str(session['filter_applied']), cell_style),
                Paragraph("<b>Total Packets:</b>", cell_bold), Paragraph(str(stats['total_packets']), cell_style)
            ],
            [
                Paragraph("<b>Total Bytes:</b>", cell_bold), Paragraph(f"{stats['total_bytes']:,} bytes", cell_style),
                Paragraph("<b>Avg Packet Size:</b>", cell_bold), Paragraph(f"{stats['avg_packet_size']} bytes", cell_style)
            ]
        ]
        meta_table = Table(meta_data, colWidths=[100, 170, 100, 170])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 14))

        # Protocol Breakdown Section
        elements.append(Paragraph("Protocol Breakdown Summary", section_style))
        proto_headers = [
            Paragraph("Protocol", cell_bold),
            Paragraph("Packets Captured", cell_bold),
            Paragraph("Percentage of Total", cell_bold)
        ]
        proto_rows = [proto_headers]
        tot = stats['total_packets'] or 1
        for proto, count in stats.get('protocol_counts', {}).items():
            pct = round((count / tot) * 100, 1)
            proto_rows.append([
                Paragraph(proto, cell_style),
                Paragraph(f"{count:,}", cell_style),
                Paragraph(f"{pct}%", cell_style)
            ])

        proto_table = Table(proto_rows, colWidths=[180, 180, 180])
        proto_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        # Change header text colors in proto_table
        for i in range(3):
            proto_headers[i].style.textColor = colors.white

        elements.append(proto_table)
        elements.append(Spacer(1, 14))

        # Top Endpoints Section
        elements.append(Paragraph("Top Network Endpoints", section_style))
        endpoint_data = [
            [Paragraph("Top Source Addresses", cell_bold), Paragraph("Top Destination Addresses", cell_bold)]
        ]
        endpoint_data[0][0].style.textColor = colors.white
        endpoint_data[0][1].style.textColor = colors.white

        top_src_str = "<br/>".join([f"{item['ip']} &mdash; {item['count']} pkts" for item in stats.get('top_sources', [])]) or "None"
        top_dst_str = "<br/>".join([f"{item['ip']} &mdash; {item['count']} pkts" for item in stats.get('top_destinations', [])]) or "None"

        endpoint_data.append([
            Paragraph(top_src_str, cell_style),
            Paragraph(top_dst_str, cell_style)
        ])

        endpoint_table = Table(endpoint_data, colWidths=[270, 270])
        endpoint_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        elements.append(endpoint_table)
        elements.append(Spacer(1, 14))

        # Sample Packet Records Table (Up to 15 packets)
        elements.append(Paragraph("Packet Sample Log (First 15 Recorded Packets)", section_style))
        sample_headers = [
            Paragraph("#", cell_bold),
            Paragraph("Time", cell_bold),
            Paragraph("Source IP", cell_bold),
            Paragraph("Destination IP", cell_bold),
            Paragraph("Proto", cell_bold),
            Paragraph("Len", cell_bold),
            Paragraph("Info", cell_bold)
        ]
        for h in sample_headers:
            h.style.textColor = colors.white

        sample_rows = [sample_headers]
        for p in packets[:15]:
            sample_rows.append([
                Paragraph(str(p.get("packet_number")), cell_style),
                Paragraph(str(p.get("formatted_time", ""))[-12:], cell_style),
                Paragraph(str(p.get("ip_src") or "N/A"), cell_style),
                Paragraph(str(p.get("ip_dst") or "N/A"), cell_style),
                Paragraph(str(p.get("protocol")), cell_style),
                Paragraph(str(p.get("packet_len")), cell_style),
                Paragraph(str(p.get("info", ""))[:32], cell_style)
            ])

        sample_table = Table(sample_rows, colWidths=[25, 65, 95, 95, 45, 35, 180])
        sample_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        elements.append(sample_table)

        # Footer Notice
        elements.append(Spacer(1, 20))
        notice_style = ParagraphStyle(
            'Notice',
            parent=styles['Normal'],
            fontSize=7,
            textColor=colors.HexColor('#64748b')
        )
        elements.append(Paragraph(
            "Notice: PacketScope is designed strictly for educational network analysis and authorized security monitoring. "
            "Sensitive application payloads are redacted. Generated automatically by PacketScope Engine.",
            notice_style
        ))

        # Build PDF
        doc.build(elements)

        # Log export
        file_size = os.path.getsize(pdf_path)
        DatabaseManager.log_export(session_id, "pdf", pdf_filename, file_size)

        return pdf_path
